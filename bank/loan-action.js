import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

// 1. SYSTEM ENVIRONMENT INITIALIZATION
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL CONFIGURATION ERROR: Supabase or JWT credential mappings are unassigned inside environment properties.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
}

export default async function loanActionHandler(req, res) {
    // A. CORS & OPTION METHOD INTERCEPTORS
    const requestOrigin = req.headers.origin;
    if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

    // B. AUTHENTICATION & SECURITY VALIDATION LAYERS
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Access denied. Token missing." });
    }

    const token = authHeader.split(" ")[1];
    let decodedUser;
    try {
        decodedUser = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(403).json({ success: false, error: "Session token expired or corrupted." });
    }

    const userUuid = decodedUser.uuid;
    const signature = decodedUser.signature;

    if (!signature) {
        return res.status(400).json({ success: false, error: "Deployment boundary tracking signature missing from token properties." });
    }

    const dynamicPlatformName = formatPlatformName(signature);

    // C. EXTRACT WORKFLOW DEPLOYMENT PAYLOAD PARAMETERS
    const {
        loanApprovalStatus,
        loanType,
        loanAmount,
        loan_duration,
        signature: clientSignature,
        accountBalance,
        accountTypeBalance,
        selectedSourceChannel
    } = req.body;

    try {
        // 1. Fetch Dynamic SMTP Engine Credentials directly from the admin workspace matching signature
        const { data: adminRecord, error: adminError } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email, website_name")
            .eq("signature", signature)
            .maybeSingle();

        if (adminError || !adminRecord) {
            return res.status(500).json({ success: false, error: "Administrative network workspace profile parsing exception fault." });
        }

        const platformLabel = adminRecord.website_name || dynamicPlatformName;

        // 2. Locate and check the targeted client row data
        const { data: userRecord, error: userError } = await supabase
            .from("users")
            .select("email, firstname, lastname, currency, loanAmount, accountBalance, accountTypeBalance")
            .eq("uuid", userUuid)
            .maybeSingle();

        if (userError || !userRecord) {
            return res.status(444).json({ success: false, error: "Target account identity matrix parameters lookup returned null references." });
        }

        const userCurrency = userRecord.currency || "$";
        const isPayback = (String(loanApprovalStatus).toLowerCase().trim() === "no");

        // Generate uniform date format string matching local tracking specifications
        const formattedDateString = new Date().toLocaleDateString("en-US", {
            year: "numeric",
            month: "short",
            day: "numeric"
        });

        // D. COMPOSE AND DISPATCH UPDATES ONTO DATABASE
        let updatePayload = {};
        let historyEntries = [];

        const selectedChannelText = selectedSourceChannel === "accountTypeBalance" ? "Vault Account Balance" : "Primary Account Balance";
        const targetSourceBalance = selectedSourceChannel === "accountTypeBalance" ? accountTypeBalance : accountBalance;

        // Calculate principal variables for history tracking values matrix
        let displayDebtAmount = "0.00";

        if (isPayback) {
            const principalBase = parseFloat(userRecord.loanAmount || 0);
            const absoluteTotalDebt = principalBase + (principalBase * 0.05); // Standard 5% interest logic matching frontend
            displayDebtAmount = absoluteTotalDebt.toFixed(2);

            updatePayload = {
                accountBalance: String(accountBalance),
                accountTypeBalance: String(accountTypeBalance),
                loanApprovalStatus: "", // Reset status to null/empty string on complete repayment settlement
                loanType: "",
                loanAmount: "0",
                loan_duration: "",
                signature: clientSignature || "Signed electronically via OnFlex Vault Node Engine"
            };

            // Inject repayment history matrix trace parameter object
            historyEntries.push({
                date: formattedDateString,
                amount: String(displayDebtAmount),
                bankName: platformLabel,
                status: "Successful",
                withdrawFrom: selectedChannelText,
                name: `${userRecord.firstname} ${userRecord.lastname}`.trim(),
                description: `Debt Settlement - Sourced via ${selectedChannelText} (Remaining Debt: ${userCurrency}0.00)`,
                transactionType: "Debit",
                uuid: userUuid,
                signature: signature,
                tax_charge: null
            });
        } else {
            displayDebtAmount = parseFloat(loanAmount || 0).toFixed(2);

            updatePayload = {
                loanApprovalStatus: "Pending",
                loanType: loanType,
                loanAmount: String(loanAmount),
                loan_duration: loan_duration,
                signature: clientSignature || "Signed electronically via OnFlex Vault Node Engine"
            };

            // Inject loan application history matrix trace parameter object
            historyEntries.push({
                date: formattedDateString,
                amount: String(displayDebtAmount),
                bankName: platformLabel,
                status: "Pending",
                withdrawFrom: "Loan Allocation Ledger",
                name: `${userRecord.firstname} ${userRecord.lastname}`.trim(),
                description: `Applied for ${loanType} loan allocation (${loan_duration})`,
                transactionType: "Credit",
                uuid: userUuid,
                signature: signature,
                tax_charge: null
            });
        }

        // Step 1: Commit User Table Updates
        const { error: dbUpdateError } = await supabase
            .from("users")
            .update(updatePayload)
            .eq("uuid", userUuid);

        if (dbUpdateError) {
            throw new Error(`Supabase client write engine failure pipeline: ${dbUpdateError.message}`);
        }

        // Step 2: Commit History Table Entry Records
        const { error: historyInsertError } = await supabase.from("history").insert(historyEntries);
        if (historyInsertError) {
            console.error("⚠️ History Ledger Record Insertion Fault Trace:", historyInsertError.message);
        }

        // E. FIRE BACKGROUND SMTP TRANSMISSION ENGINE USING CAPTURED DB TOKENS
        try {
            const mailTransporter = nodemailer.createTransport({
                host: adminRecord.smtp_host,
                port: adminRecord.smtp_port,
                auth: {
                    user: adminRecord.smtp_email,
                    pass: adminRecord.smtp_password
                }
            });

            const emailDomain = adminRecord.smtp_email ? adminRecord.smtp_email.split("@")[1] : "platform.com";
            const noReplyHeader = `"No-Reply Automated System" <no-reply@${emailDomain}>`;

            const formattedAmount = parseFloat(loanAmount || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
            const currentFinalBalance = parseFloat(targetSourceBalance || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
            const formattedDebtDisplay = parseFloat(displayDebtAmount).toLocaleString('en-US', { minimumFractionDigits: 2 });

            // OPTIMIZED USER SUBJECT LINE (Anti-Spam Optimized)
            const clientSubject = isPayback
                ? `Loan Repayment Confirmation - Thank you, ${userRecord.firstname || "User"}`
                : `[Application Transmitted] Loan Parameters Logged - ${platformLabel}`;

            const adminSubject = isPayback
                ? `🚨 [LOAN SETTLEMENT ALERT] User Outstanding Debt Liquidated`
                : `🚨 [LOAN APPLICATION ALERT] New Pending Review Case Logged`;

            // OPTIMIZED USER REPAYMENT BODY COPY (Anti-Spam Optimized Layout)
            const clientHtmlBody = isPayback ? `
                <div style="font-family: Arial, sans-serif; background-color: #f8fafc; padding: 30px 10px; color: #334155;">
                    <div style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
                        <div style="background-color: #059669; padding: 24px; text-align: center;">
                            <h2 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: bold;">Repayment Received</h2>
                        </div>
                        <div style="padding: 30px; line-height: 1.6; font-size: 15px;">
                            <p style="margin-top: 0;">Dear ${userRecord.firstname || "User"},</p>
                            <p>We are writing to confirm that your loan repayment has been successfully processed. Your outstanding balance for this loan has been updated to zero.</p>
                            
                            <div style="background-color: #f1f5f9; padding: 20px; border-radius: 6px; margin: 24px 0;">
                                <h4 style="margin: 0 0 12px 0; color: #1e293b; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">Transaction Breakdown</h4>
                                <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
                                    <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 10px 0; color: #64748b;">Payment Source:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #1e293b;">${selectedChannelText}</td></tr>
                                    <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 10px 0; color: #64748b;">Amount Paid:</td><td style="text-align: right; padding: 10px 0; font-weight: 700; color: #b91c1c;">-${userCurrency}${formattedDebtDisplay}</td></tr>
                                    <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 10px 0; color: #64748b;">Updated Account Balance:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #059669;">${userCurrency}${currentFinalBalance}</td></tr>
                                    <tr><td style="padding: 10px 0; color: #64748b;">Remaining Loan Balance:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #475569;">${userCurrency}0.00</td></tr>
                                </table>
                            </div>
                            
                            <p style="color: #64748b; font-size: 13px; text-align: center; margin-bottom: 0; margin-top: 25px;">This is an automated notification. Please do not reply directly to this email.</p>
                        </div>
                        <div style="background-color: #f8fafc; padding: 16px; text-align: center; border-top: 1px solid #e2e8f0;">
                            <span style="font-size: 12px; color: #94a3b8;">&copy; ${formattedDateString.split(',').pop().trim()} ${platformLabel}. All rights reserved.</span>
                        </div>
                    </div>
                </div>`
                : `
                <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: #0b0b0e; padding: 40px 20px;">
                    <div style="max-width: 560px; margin: 0 auto; background: #111115; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; overflow: hidden; box-shadow: 0 8px 24px rgba(0,0,0,0.3);">
                        <div style="background: #0a698f; padding: 24px; text-align: center;">
                            <h2 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 600; letter-spacing: 0.5px;">Credit Portfolio Parameters Received</h2>
                        </div>
                        <div style="padding: 30px; color: #e2e8f0; line-height: 1.6; font-size: 14px;">
                            <p style="margin-top: 0; font-size: 15px;">Hello ${userRecord.firstname || "User"},</p>
                            <p style="color: #94a3b8;">Your documentation tracking profile application has successfully cleared pre-routing validations and is undergoing secondary verification analysis.</p>
                            
                            <div style="background: rgba(255, 255, 255, 0.02); padding: 20px; border-radius: 8px; margin: 24px 0; border: 1px solid rgba(255, 255, 255, 0.06);">
                                <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);"><td style="padding: 10px 0; color: #94a3b8;">Requested Capital:</td><td style="text-align: right; padding: 10px 0; font-weight: 700; color: #14a24a;">+${userCurrency}${formattedAmount}</td></tr>
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);"><td style="padding: 10px 0; color: #94a3b8;">Credit Category:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #ffffff;">${loanType}</td></tr>
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);"><td style="padding: 10px 0; color: #94a3b8;">Amortization Term:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #ffffff;">${loan_duration}</td></tr>
                                    <tr><td style="padding: 10px 0; color: #94a3b8;">Application Status:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #f59e0b;">Pending Clearance Review</td></tr>
                                </table>
                            </div>
                            
                            <p style="color: #8a99ad; font-size: 0.85rem; text-align: center; margin-bottom: 0; margin-top: 25px;">Compliance nodes typically resolve auditing metrics inside 24 standard processing business loops.</p>
                            <p style="font-size: 11px; color: #888888; text-align: center; margin-top: 15px;">This is an automated notification. Please do not reply directly to this email.</p>
                        </div>
                    </div>
                </div>`;

            const adminHtmlBody = `
                <div style="font-family: Arial, sans-serif; background: #f8fafc; color: #0f172a; padding: 30px; border-radius: 8px; max-width: 600px; margin: 20px auto; border: 1px solid #e2e8f0;">
                    <h3 style="color: #0f172a; border-bottom: 2px solid #cbd5e1; padding-bottom: 10px; margin-top:0;">${platformLabel} Core Security Hub System Monitor Alert</h3>
                    <p><b>Operational Action Event Frame:</b> ${isPayback ? "CREDIT_TIER_LIQUIDATION_REPAYMENT" : "NEW_LOAN_APPLICATION_SUBMITTED"}</p>
                    <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px;">
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold; width:40%;">Account Holder Reference:</td><td style="padding: 8px;">${userRecord.firstname} ${userRecord.lastname}</td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">User Account Mapping Email:</td><td style="padding: 8px;">${userRecord.email}</td></tr>
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold;">System Scope UUID:</td><td style="padding: 8px; font-family: monospace;">${userUuid}</td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">Repayment Sourced From:</td><td style="padding: 8px; font-weight: dotted;">${isPayback ? selectedChannelText : 'N/A'}</td></tr>
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold;">Source Account Balance:</td><td style="padding: 8px; font-weight: bold;">${isPayback ? userCurrency + currentFinalBalance : 'N/A'}</td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">State Verification Token:</td><td style="padding: 8px; font-weight: bold; color: ${isPayback ? '#10b981' : '#f59e0b'};">${isPayback ? "Settled (Cleared)" : "Pending"}</td></tr>
                    </table>
                    <p style="margin-top: 25px; font-size: 0.85rem; color: #64748b;">Log inside your master administration dashboard panel configuration to review adjustments.</p>
                </div>`;

            // Explicitly handle mail routing execution safely
            await Promise.all([
                mailTransporter.sendMail({
                    from: `"${platformLabel}" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: userRecord.email,
                    subject: clientSubject,
                    html: clientHtmlBody
                }),
                mailTransporter.sendMail({
                    from: `"${platformLabel} System Core Monitor" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: adminRecord.smtp_email.trim(),
                    subject: adminSubject,
                    html: adminHtmlBody
                })
            ]);

            console.log("📨 Loan interaction transaction reporting emails successfully routed.");
        } catch (mailThreadError) {
            console.warn("⚠️ Intermittent mail subsystem tracking loop warning:", mailThreadError.message);
        }

        return res.status(200).json({ success: true, message: "Transactional user record matrix update completed successfully." });

    } catch (globalExecutionFault) {
        console.error("❌ Global transaction thread logic failure:", globalExecutionFault);
        return res.status(500).json({ success: false, error: globalExecutionFault.message || "Internal database routing network fault." });
    }
}