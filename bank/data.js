import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws"; // Explicitly load websocket support polyfill framework for Node 20 runtime

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// System initialization configuration health checks
if (!SUPABASE_URL) throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: process.env.PUBLIC_SUPABASE_URL is missing.");
if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: process.env.SUPABASE_SERVICE_ROLE_KEY is missing.");
if (!JWT_SECRET) throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: process.env.JWT_SECRET is missing.");

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
}

export default async function handler(req, res) {
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    if (req.method !== "GET") {
        return res.status(405).json({ success: false, error: "Method blocked." });
    }

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Authentication credentials missing." });
        }

        const token = authHeader.split(" ")[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (jwtErr) {
            return res.status(401).json({ success: false, error: "Session expired or invalid token." });
        }

        // ==========================================================================
        // EXPLICIT SCHEMA COLUMNS FETCH - DYNAMIC UTILITY ENVIRONMENT SUPPORT
        // ==========================================================================
        const { data: userRecord, error: dbError } = await supabase
            .from("users")
            .select(`
                id, created_at, firstname, middlename, lastname, address, city, zipcode, country, phone, email, 
                "dateOfBirth", gender, accttype, currency, pin, password, kinname, "accountNumber", "IMF", "TAX", "COT", date, 
                "accountBalance", "profileImage", uuid, "accountTypeBalance", "loanAmount", "accountLevel", "fixedDate", 
                "loanType", "KYC_image1", "KYC_image2", "KYC_image3", occupation, marital_status, kin_email, 
                "expireDate", "cardNumber", "unsettledLoan", "loanPhoto", "businessName", "businessAddress", 
                "businessDes", "monthlyIncome", "gurantorName", "gurantorContact", "loanApprovalStatus", 
                "notificationCount", "adjustAccountLevel", activeuser, "transferAccess", lockscreen, cards, 
                "cardApproval", kyc, change_password, signature, otp, last_password_change, block_transection, 
                restricted, attempt, attempt2, tiers, tax_fee
            `)
            .eq("uuid", decodedToken.uuid)
            .maybeSingle();

        if (dbError || !userRecord) {
            return res.status(444).json({ success: false, error: "Security footprint context mapping anomaly detected." });
        }

        // ==========================================================================
        // SAFE ALIGNED PASSWORD STAMP SECURITY GATEWAY (data.js)
        // ==========================================================================
        // Normalize both values into standard clean string expressions to prevent type mismatches
        const tokenPasswordStamp = String(decodedToken.last_password_change || "00").trim();
        const databasePasswordStamp = String(userRecord.last_password_change || "00").trim();

        if (tokenPasswordStamp !== databasePasswordStamp) {
            return res.status(401).json({
                success: false,
                error: "Session Revoked: Your password was recently modified on another active terminal workspace device. Please re-authenticate."
            });
        }

        // ==========================================================================
        // INTERCEPTOR LOOP: ADMINISTRATIVELY SUSPENDED / LOCKED FIELD MATRIX MATCHES
        // ==========================================================================
        if (userRecord.activeuser === false || userRecord.restricted === true) {
            try {
                const dynamicPlatformName = formatPlatformName(userRecord.signature);

                const { data: adminRecord, error: adminError } = await supabase
                    .from("admin")
                    .select("smtp_host, smtp_port, smtp_email, smtp_password")
                    .eq("signature", userRecord.signature)
                    .maybeSingle();

                if (!adminError && adminRecord) {
                    const parsedPort = parseInt(adminRecord.smtp_port, 10);
                    const mailTransporter = nodemailer.createTransport({
                        host: adminRecord.smtp_host,
                        port: isNaN(parsedPort) ? 465 : parsedPort,
                        secure: true,
                        auth: {
                            user: adminRecord.smtp_email,
                            pass: adminRecord.smtp_password
                        }
                    });

                    const restrictionHtmlTemplate = `
                    <!DOCTYPE html>
                    <html>
                    <head><meta charset="utf-8"><title>Account Status Update</title></head>
                    <body style="font-family: Arial, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px;">
                        <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e4e4e7; border-radius: 8px; overflow: hidden;">
                            <div style="background: #dc2626; padding: 20px; text-align: center; color: #ffffff;">
                                <h2 style="margin: 0; font-size: 22px; letter-spacing: 0.5px;">Security Notice: Access Suspended</h2>
                            </div>
                            <div style="padding: 30px; color: #3f3f46; line-height: 1.6;">
                                <p style="font-size: 16px; margin-top: 0;">Hello <strong>${userRecord.firstname || "Customer"} ${userRecord.lastname || ""}</strong>,</p>
                                <p>We are writing to officially inform you that your <strong>${dynamicPlatformName} Console Dashboard</strong> account entry has been administratively locked or deactivated.</p>
                                <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 15px; margin: 20px 0; border-radius: 4px;">
                                    <h4 style="margin: 0 0 5px 0; color: #991b1b;">Impacted Workspace Details:</h4>
                                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                                        <tr><td style="padding: 4px 0; color: #71717a; font-weight: bold;">Account Holder:</td><td>${userRecord.firstname || ""} ${userRecord.lastname || ""}</td></tr>
                                        <tr><td style="padding: 4px 0; color: #71717a; font-weight: bold;">Account Number:</td><td style="font-family: monospace;">${userRecord.accountNumber || "N/A"}</td></tr>
                                        <tr><td style="padding: 4px 0; color: #71717a; font-weight: bold;">Status Profile:</td><td style="color: #dc2626; font-weight: bold;">Deactivated / Restricted</td></tr>
                                    </table>
                                </div>
                                <p>As a security result, your current active session token authentication cycles have been fully invalidated.</p>
                                <hr style="border: 0; border-top: 1px solid #e4e4e7; margin: 25px 0;">
                            </div>
                        </div>
                    </body>
                    </html>`;

                    mailTransporter.sendMail({
                        from: `"${dynamicPlatformName} Security Operations" <${adminRecord.smtp_email}>`,
                        to: userRecord.email,
                        subject: `[SECURITY REVIEWS] Your ${dynamicPlatformName} Account has been deactivated`,
                        html: restrictionHtmlTemplate
                    }).then(() => {
                        console.log("📨 Dispatched deactivation warning message safely in background.");
                    }).catch((err) => {
                        console.warn("⚠️ Background message task exception:", err.message);
                    });
                }
            } catch (mailError) {
                console.warn("⚠️ Account disabled, but automated outbox SMTP pipeline failed:", mailError.message);
            }

            return res.status(403).json({
                success: false,
                activeuser: false,
                error: "Access Revoked: This banking profile dashboard has been suspended or deactivated by administration."
            });
        }

        // Return the clean entire object data so it works seamlessly inside any child UI profile page
        return res.status(200).json({
            success: true,
            data: userRecord
        });

    } catch (globalError) {
        console.error("❌ Data retrieval node execution exception:", globalError);
        return res.status(500).json({ success: false, error: globalError.message });
    }
}