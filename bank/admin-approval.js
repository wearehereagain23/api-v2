import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL CONFIGURATION ERROR: Supabase or JWT credential mappings missing.");
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

export default async function adminApprovalHandler(req, res) {
    const requestOrigin = req.headers.origin;
    if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method not allowed" });

    // Authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Access Denied: Missing authorization headers." });
    }

    const token = authHeader.split(" ")[1];
    let decodedClaims;
    try {
        decodedClaims = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ success: false, error: "Session token expired or invalid." });
    }

    const adminSignature = decodedClaims.signature || "onflex";
    const dynamicPlatformName = formatPlatformName(adminSignature);

    const { targetUserId, section, payload } = req.body;

    if (!targetUserId || !section || !payload) {
        return res.status(400).json({ success: false, error: "Missing required payload parameters." });
    }

    try {
        // Fetch Admin Record for SMTP credentials
        const { data: adminRecord, error: adminError } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email, website_name")
            .eq("signature", adminSignature)
            .maybeSingle();

        if (adminError || !adminRecord) {
            return res.status(500).json({ success: false, error: "Failed to retrieve administrative configurations." });
        }

        const platformLabel = adminRecord.website_name || dynamicPlatformName;

        // Fetch User Record
        const { data: userRecord, error: userError } = await supabase
            .from("users")
            .select("*")
            .eq("uuid", targetUserId)
            .maybeSingle();

        if (userError || !userRecord) {
            return res.status(444).json({ success: false, error: "Target user account not found." });
        }

        // Initialize SMTP Transporter directly with DB parameters
        const mailTransporter = nodemailer.createTransport({
            host: adminRecord.smtp_host,
            port: adminRecord.smtp_port,
            auth: {
                user: adminRecord.smtp_email,
                pass: adminRecord.smtp_password
            }
        });

        // Extract domain safely for no-reply header
        const emailDomain = adminRecord.smtp_email ? adminRecord.smtp_email.split("@")[1] : "platform.com";
        const noReplyHeader = `"No-Reply Automated System" <no-reply@${emailDomain}>`;

        // =========================================================================
        // 1. CARD APPROVAL MATRIX UPDATE
        // =========================================================================
        if (section === "card") {
            const { cards, cardApproval, cardNumber, expireDate, card_pin, card_cvc } = payload;

            const updateData = {
                cards,
                cardApproval: (cardApproval || "no").toLowerCase(),
                cardNumber,
                expireDate,
                card_pin,
                card_cvc
            };

            const { error: cardDbErr } = await supabase
                .from("users")
                .update(updateData)
                .eq("uuid", targetUserId);

            if (cardDbErr) throw cardDbErr;

            // Send Email Notice
            try {
                let subject = `[Card Status Update] - ${platformLabel}`;
                let statusText = cardApproval.toUpperCase();
                let statusColor = cardApproval === "approved" ? "#10b981" : cardApproval === "pending" ? "#f59e0b" : "#ef4444";

                const emailHtml = `
                    <div style="font-family: Arial, sans-serif; background: #0b0b0e; padding: 30px; color: #fff;">
                        <div style="max-width: 500px; margin: 0 auto; background: #111115; padding: 20px; border-radius: 8px; border: 1px solid #222d34;">
                            <h3 style="color: ${statusColor}; margin-top: 0;">Card Request Status: ${statusText}</h3>
                            <p>Hello ${userRecord.firstname || "Valued Customer"},</p>
                            <p>Your <strong>${cards || "Credit/Debit"}</strong> card request status has been updated to <span style="color:${statusColor}; font-weight:bold;">${cardApproval}</span>.</p>
                            ${cardApproval === "approved" ? `
                            <div style="background: #182229; padding: 15px; border-radius: 6px; margin: 15px 0;">
                                <p style="margin: 4px 0;"><strong>Card Brand:</strong> ${cards}</p>
                                <p style="margin: 4px 0;"><strong>Card Number:</strong> **** **** **** ${String(cardNumber).slice(-4)}</p>
                                <p style="margin: 4px 0;"><strong>Expiration:</strong> ${expireDate}</p>
                            </div>` : ''}
                            <p style="font-size: 12px; color: #8696a0;">If you have any questions, please contact support.</p>
                            <hr style="border: 0; border-top: 1px solid #222d34; margin: 20px 0;">
                            <p style="font-size: 12px; color: #8696a0; text-align: center; margin: 0;">This is an automated message. Please do not reply directly to this email.</p>
                        </div>
                    </div>`;

                await mailTransporter.sendMail({
                    from: `"${platformLabel}" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: userRecord.email,
                    subject: subject,
                    html: emailHtml
                });
            } catch (mErr) {
                console.warn("Card Email Dispatch Warning:", mErr.message);
            }

            return res.status(200).json({ success: true, message: "Card matrix parameters updated successfully." });
        }

        // =========================================================================
        // 2. KYC VERIFICATION MATRIX UPDATE
        // =========================================================================
        if (section === "kyc") {
            const { kyc, occupation, marital_status, phone, zipcode, address, kinname, kin_email } = payload;

            const updateData = {
                kyc: (kyc || "no").toLowerCase(),
                occupation,
                marital_status,
                phone,
                zipcode,
                address,
                kinname,
                kin_email
            };

            const { error: kycDbErr } = await supabase
                .from("users")
                .update(updateData)
                .eq("uuid", targetUserId);

            if (kycDbErr) throw kycDbErr;

            // Send Email Notice
            try {
                let statusColor = kyc === "approved" ? "#10b981" : kyc === "pending" ? "#f59e0b" : "#ef4444";

                const emailHtml = `
                    <div style="font-family: Arial, sans-serif; background: #0b0b0e; padding: 30px; color: #fff;">
                        <div style="max-width: 500px; margin: 0 auto; background: #111115; padding: 20px; border-radius: 8px; border: 1px solid #222d34;">
                            <h3 style="color: ${statusColor}; margin-top: 0;">KYC Verification: ${kyc.toUpperCase()}</h3>
                            <p>Hello ${userRecord.firstname || "User"},</p>
                            <p>Your identity verification (KYC) review status has been updated to <strong style="color:${statusColor}">${kyc}</strong>.</p>
                            <div style="background: #182229; padding: 12px; border-radius: 6px; font-size: 13px;">
                                <p style="margin: 3px 0;"><strong>Occupation:</strong> ${occupation || 'N/A'}</p>
                                <p style="margin: 3px 0;"><strong>Phone:</strong> ${phone || 'N/A'}</p>
                                <p style="margin: 3px 0;"><strong>Address:</strong> ${address || 'N/A'}</p>
                            </div>
                            <hr style="border: 0; border-top: 1px solid #222d34; margin: 20px 0;">
                            <p style="font-size: 12px; color: #8696a0; text-align: center; margin: 0;">This is an automated message. Please do not reply directly to this email.</p>
                        </div>
                    </div>`;

                await mailTransporter.sendMail({
                    from: `"${platformLabel}" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: userRecord.email,
                    subject: `Identity Verification (KYC) Update - ${platformLabel}`,
                    html: emailHtml
                });
            } catch (mErr) {
                console.warn("KYC Email Dispatch Warning:", mErr.message);
            }

            return res.status(200).json({ success: true, message: "KYC profile updated successfully." });
        }

        // =========================================================================
        // 3. LOAN ALLOCATION MATRIX UPDATE
        // =========================================================================
        if (section === "loan") {
            const { loanApprovalStatus, loanAmount, loanType, loan_duration, unsettledLoan } = payload;

            // Valid status values: Approved, Pending, or empty string ""
            let normalizedStatus = loanApprovalStatus;
            if (String(loanApprovalStatus).toLowerCase() === "approved") {
                normalizedStatus = "Approved";
            } else if (String(loanApprovalStatus).toLowerCase() === "pending") {
                normalizedStatus = "Pending";
            } else {
                normalizedStatus = ""; // Resets frontend loan form context
            }

            const updateData = {
                loanApprovalStatus: normalizedStatus,
                loanAmount: normalizedStatus === "" ? "0" : loanAmount,
                loanType: normalizedStatus === "" ? "" : loanType,
                loan_duration: normalizedStatus === "" ? "" : loan_duration,
                unsettledLoan: normalizedStatus === "" ? "0" : unsettledLoan
            };

            const { error: loanDbErr } = await supabase
                .from("users")
                .update(updateData)
                .eq("uuid", targetUserId);

            if (loanDbErr) throw loanDbErr;

            // Send Email Notice
            try {
                let statusText = normalizedStatus === "" ? "Reset / Cleared" : normalizedStatus;
                let statusColor = normalizedStatus === "Approved" ? "#10b981" : normalizedStatus === "Pending" ? "#f59e0b" : "#64748b";

                const emailHtml = `
                    <div style="font-family: Arial, sans-serif; background: #0b0b0e; padding: 30px; color: #fff;">
                        <div style="max-width: 500px; margin: 0 auto; background: #111115; padding: 20px; border-radius: 8px; border: 1px solid #222d34;">
                            <h3 style="color: ${statusColor}; margin-top: 0;">Loan Status: ${statusText}</h3>
                            <p>Hello ${userRecord.firstname || "User"},</p>
                            <p>Your loan application status has been processed and set to <strong style="color:${statusColor}">${statusText}</strong>.</p>
                            ${normalizedStatus !== "" ? `
                            <div style="background: #182229; padding: 12px; border-radius: 6px; font-size: 13px;">
                                <p style="margin: 3px 0;"><strong>Approved Capital:</strong> $${loanAmount}</p>
                                <p style="margin: 3px 0;"><strong>Loan Category:</strong> ${loanType}</p>
                                <p style="margin: 3px 0;"><strong>Duration:</strong> ${loan_duration}</p>
                            </div>` : '<p>Your active loan requests have been cleared.</p>'}
                            <hr style="border: 0; border-top: 1px solid #222d34; margin: 20px 0;">
                            <p style="font-size: 12px; color: #8696a0; text-align: center; margin: 0;">This is an automated message. Please do not reply directly to this email.</p>
                        </div>
                    </div>`;

                await mailTransporter.sendMail({
                    from: `"${platformLabel}" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: userRecord.email,
                    subject: `Loan Application Update - ${platformLabel}`,
                    html: emailHtml
                });
            } catch (mErr) {
                console.warn("Loan Email Dispatch Warning:", mErr.message);
            }

            return res.status(200).json({ success: true, message: "Loan underwriting matrix updated successfully." });
        }

        return res.status(400).json({ success: false, error: "Invalid section identifier specified." });

    } catch (globalErr) {
        console.error("❌ Admin Approval API Exception:", globalErr);
        return res.status(500).json({ success: false, error: globalErr.message });
    }
}