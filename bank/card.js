import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

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
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "Method Not Allowed" });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Authentication failed: Token omitted." });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decodedClaims = jwt.verify(token, JWT_SECRET);
        const targetUserId = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);

        if (!targetUserId) {
            return res.status(401).json({ success: false, error: "Unauthorized: Invalid token session footprint." });
        }

        const { action, cardType, pin, signature } = req.body;

        if (!signature) {
            return res.status(400).json({ success: false, error: "Bad Request: Missing deployment 'signature' tracking string." });
        }

        // Query User row and Admin configuration context
        const [userRes, adminRes] = await Promise.all([
            supabase.from("users").select("*").eq("uuid", targetUserId).single(),
            supabase.from("admin").select("smtp_host, smtp_port, smtp_password, smtp_email, signature, website_name").eq("signature", signature).maybeSingle()
        ]);

        if (userRes.error || !userRes.data) {
            return res.status(404).json({ success: false, error: "User session profile matrix mismatch." });
        }
        if (adminRes.error || !adminRes.data) {
            return res.status(401).json({ success: false, error: `Authentication Failed: No administrative environment found matching signature string '${signature}'.` });
        }

        const userRecord = userRes.data;
        const adminRecord = adminRes.data;
        const dynamicPlatformName = formatPlatformName(adminRecord.signature || adminRecord.website_name || "OnFlex");

        // Fail instantly if the target profile is flagged as locked/restricted
        if (userRecord.restricted === true || userRecord.activeuser === false) {
            return res.status(403).json({ success: false, error: "Access Denied: Secure account access parameters locked." });
        }

        // ==========================================================================
        // ACTION: VERIFY PIN - STRICTLY VALIDATES PRIMARY USER PIN ONLY
        // ==========================================================================
        if (action === "verify_pin") {
            const dbUserPin = userRecord.pin ? String(userRecord.pin).trim() : "";
            const inputPin = String(pin || "").trim();

            if (userRecord.restricted === true || userRecord.activeuser === false || (parseInt(userRecord.attempt, 10) >= 5)) {
                return res.status(403).json({
                    success: false,
                    error: "Access Denied: This security profile is restricted due to previous violations."
                });
            }

            if (!dbUserPin || dbUserPin === "") {
                return res.status(400).json({ success: false, error: "No user authentication PIN configured for this account profile." });
            }

            if (dbUserPin !== inputPin) {
                const lastKnownAttempt = parseInt(userRecord.attempt, 10) || 0;
                const attemptsUsed = lastKnownAttempt + 1;
                const totalRemainingAttempts = 5 - attemptsUsed;

                if (totalRemainingAttempts <= 0) {
                    await supabase
                        .from("users")
                        .update({ restricted: true, activeuser: false, attempt: 5 })
                        .eq("uuid", userRecord.uuid);

                    return res.status(403).json({
                        success: false,
                        account_locked: true,
                        error: "Security violations boundary reached. This profile is now restricted."
                    });
                }

                await supabase
                    .from("users")
                    .update({ attempt: attemptsUsed })
                    .eq("uuid", userRecord.uuid);

                return res.status(401).json({
                    success: false,
                    account_locked: false,
                    error: `Invalid verification PIN. You have ${totalRemainingAttempts} remaining attempts.`
                });
            }

            // Clean pass: Reset attempt values to zero on success
            await supabase
                .from("users")
                .update({ attempt: 0, restricted: false, activeuser: true })
                .eq("uuid", userRecord.uuid);

            return res.status(200).json({ success: true, message: "User security credentials verified successfully." });
        }

        // ==========================================================================
        // ACTION: SUBMIT CARD APPLICATION (CONSOLIDATED WITH SMTP EMAIL WORKFLOW)
        // ==========================================================================
        if (action === "request_card") {
            const kycCheck = String(userRecord.kyc || userRecord.kycStatus || userRecord.verifyAccountStatus || "").toLowerCase();
            if (kycCheck !== "approved") {
                return res.status(403).json({ success: false, error: "User needs to complete KYC steps to get a card." });
            }

            const { error: updateError } = await supabase
                .from("users")
                .update({
                    cards: cardType,
                    cardApproval: "pending",
                    card_pin: String(pin).trim() // Directly set card_pin from frontend UI entry
                })
                .eq("uuid", userRecord.uuid);

            if (updateError) throw updateError;

            // Secure, scoped SMTP configuration block execution
            try {
                const parsedPort = parseInt(adminRecord.smtp_port, 10);
                const mailTransporter = nodemailer.createTransport({
                    host: adminRecord.smtp_host,
                    port: isNaN(parsedPort) ? 465 : parsedPort,
                    secure: parsedPort === 465,
                    auth: {
                        user: adminRecord.smtp_email,
                        pass: adminRecord.smtp_password
                    }
                });

                const clientHtml = `
                    <div style="font-family:sans-serif; background:#111115; color:#fff; padding:30px; border-radius:12px;">
                        <h2 style="color:#0a698f;">Card Application Under Review</h2>
                        <p>Hello ${userRecord.firstname || 'Client'},</p>
                        <p>Your request for a premium <strong>${cardType.toUpperCase()}</strong> card has been recorded. Your application status is currently pending preview and will be attended to immediately.</p>
                        <br><small>Ref ID: ${dynamicPlatformName}-CARD-${userRecord.uuid}</small>
                    </div>`;

                await mailTransporter.sendMail({
                    from: `"${dynamicPlatformName} Asset Hub" <${adminRecord.smtp_email}>`,
                    to: userRecord.email,
                    subject: `Your ${dynamicPlatformName} Card Request is under preview`,
                    html: clientHtml
                });

                const adminHtml = `
                    <div style="font-family:sans-serif; background:#111115; color:#fff; padding:30px; border-radius:12px; border:1px solid #ff9f43;">
                        <h2 style="color:#ff9f43;">Action Required: Card Application Awaiting Approval</h2>
                        <p><strong>Applicant Name:</strong> ${userRecord.firstname} ${userRecord.lastname}</p>
                        <p><strong>Account ID:</strong> ${userRecord.accountNumber || userRecord.uuid}</p>
                        <p><strong>Network Selection requested:</strong> ${cardType.toUpperCase()}</p>
                    </div>`;

                await mailTransporter.sendMail({
                    from: `"${dynamicPlatformName} Security Matrix" <${adminRecord.smtp_email}>`,
                    to: adminRecord.smtp_email,
                    subject: `[ALERT] Pending Card Activation Node Assignment`,
                    html: adminHtml
                });

                console.log("📨 Outbox dispatch sequences finished cleanly.");
            } catch (err) {
                console.error("⚠️ SMTP service pipeline connection error:", err.message);
            }

            return res.status(200).json({ success: true, message: "Application locked into pending status cleanly." });
        }

        // ==========================================================================
        // ACTION: MODIFY CARD PIN CODE MATRIX
        // ==========================================================================
        if (action === "update_pin") {
            const { error: pinError } = await supabase
                .from("users")
                .update({ card_pin: String(pin).trim() })
                .eq("uuid", userRecord.uuid);

            if (pinError) throw pinError;

            return res.status(200).json({ success: true, message: "Card transaction PIN re-keyed successfully." });
        }

        return res.status(400).json({ success: false, error: "Invalid action routing parameter provided." });

    } catch (globalError) {
        console.error("❌ Card execution context error:", globalError);
        return res.status(500).json({ success: false, error: globalError.message });
    }
}