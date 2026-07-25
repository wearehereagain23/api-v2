import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";
import nodemailer from "nodemailer"; // Added for email alerts

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

const executionAntiSpamCache = new Map();

// Helper: Format platform name
function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
}

// Helper: Get Admin SMTP Transporter
async function getAdminTransporter(signature) {
    const { data: adminRecord, error } = await supabase
        .from("admin")
        .select("smtp_host, smtp_port, smtp_password, smtp_email")
        .eq("signature", signature)
        .maybeSingle();

    if (error || !adminRecord) {
        throw new Error(error ? error.message : `No admin environment found for signature '${signature}'.`);
    }

    const parsedPort = parseInt(adminRecord.smtp_port, 10);
    const transporter = nodemailer.createTransport({
        host: adminRecord.smtp_host,
        port: isNaN(parsedPort) ? 465 : parsedPort,
        secure: true,
        auth: {
            user: adminRecord.smtp_email,
            pass: adminRecord.smtp_password
        }
    });

    return { transporter, adminEmail: adminRecord.smtp_email };
}

export default async function handler(req, res) {
    // -------------------------------------------------------------------------
    // CORS HEADERS & PREFLIGHT GATEWAY
    // -------------------------------------------------------------------------
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    const operationalSettingTarget = req.headers["x-setting-target"] || req.headers["X-Setting-Target"];
    const requestPayload = req.body || {};

    // ==========================================================================
    // AUTHENTICATED USER SESSION PIPELINE
    // ==========================================================================
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Session token is missing." });
        }

        const token = authHeader.split(" ")[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ success: false, error: "Session expired or invalid. Please log in again." });
        }

        // Extract identifier safely across all possible JWT key conventions
        const userIdentifier = decodedToken.uuid || decodedToken.id || decodedToken.sub || decodedToken.email;

        if (!userIdentifier) {
            return res.status(401).json({ success: false, error: "Invalid session payload structure." });
        }

        // Query extended columns (added firstname, lastname, signature, accountNumber) for email notifications
        let userData = null;
        const { data: userRecord, error: userError } = await supabase
            .from("users")
            .select("id, uuid, pin, email, activeuser, restricted, attempt2, kyc, card_pin, signature, firstname, lastname, accountNumber")
            .eq("uuid", userIdentifier)
            .maybeSingle();

        if (userError) {
            console.error("Supabase user query error:", userError.message);
        }

        if (userRecord) {
            userData = userRecord;
        } else {
            // Fallback check by email if uuid lookup didn't match
            const { data: byEmail } = await supabase
                .from("users")
                .select("id, uuid, pin, email, activeuser, restricted, attempt2, kyc, card_pin, signature, firstname, lastname, accountNumber")
                .eq("email", userIdentifier)
                .maybeSingle();

            userData = byEmail;
        }

        if (!userData) {
            return res.status(404).json({ success: false, error: "User session account not found." });
        }

        if (userData.restricted === true || userData.activeuser === false) {
            return res.status(403).json({ success: false, restricted: true, error: "Account access restricted." });
        }

        if (req.method === "GET") {
            return res.status(200).json({
                success: true,
                email: userData.email || ""
            });
        }

        if (req.method !== "POST") {
            return res.status(405).json({ success: false, error: "Method not allowed." });
        }

        // Anti-spam request throttling (2000ms window)
        const currentExecutionTimestamp = Date.now();
        const absoluteUserTrackerIdKey = userData.uuid || userData.id;
        if (executionAntiSpamCache.has(absoluteUserTrackerIdKey)) {
            const previousLogTime = executionAntiSpamCache.get(absoluteUserTrackerIdKey);
            if (currentExecutionTimestamp - previousLogTime < 2000) {
                return res.status(429).json({
                    success: false,
                    error: "Please wait a few seconds before submitting again."
                });
            }
        }
        executionAntiSpamCache.set(absoluteUserTrackerIdKey, currentExecutionTimestamp);

        const actionType = requestPayload.action || operationalSettingTarget;

        // -------------------------------------------------------------------------
        // TARGET ROUTE 1: CARD APPLICATION REQUEST
        // -------------------------------------------------------------------------
        if (actionType === "request_card") {
            const { cardType, pin } = requestPayload;

            if (!cardType || !pin) {
                return res.status(400).json({ success: false, error: "Card type and PIN configuration are required." });
            }

            if (!/^[0-9]{4}$/.test(String(pin).trim())) {
                return res.status(400).json({ success: false, error: "Card PIN must be exactly 4 digits." });
            }

            // Update user record with card details and new PIN
            const { error: cardApplyErr } = await supabase
                .from("users")
                .update({
                    pin: String(pin).trim(),
                    card_pin: String(pin).trim(),
                    cards: String(cardType).toLowerCase(),
                    cardApproval: "pending",
                    attempt2: 0
                })
                .eq("id", userData.id);

            if (cardApplyErr) {
                throw new Error("Failed to process card application.");
            }

            // MESSAGE USER & ALERT ADMIN
            try {
                // 1. Insert an in-app message into the DB for the user to see
                await supabase.from("messages").insert({
                    user_id: userData.uuid,
                    title: "Card Application Received",
                    message: `We have successfully received your request for a new ${cardType} card. It is currently undergoing review.`,
                    date: new Date().toISOString(),
                    read: false
                });

                // 2. Fetch Admin Transporter
                const { transporter, adminEmail } = await getAdminTransporter(userData.signature);
                const platformName = formatPlatformName(userData.signature);

                // 3. Email Alert to Admin
                await transporter.sendMail({
                    from: `"${platformName} Alerts" <${adminEmail}>`,
                    to: adminEmail,
                    subject: `Pending Card Application: ${userData.firstname} ${userData.lastname}`,
                    html: `
                        <h3>New Card Application Alert</h3>
                        <p><strong>Customer Name:</strong> ${userData.firstname} ${userData.lastname}</p>
                        <p><strong>Email:</strong> ${userData.email}</p>
                        <p><strong>Account Number:</strong> ${userData.accountNumber || "N/A"}</p>
                        <p><strong>Requested Card Type:</strong> ${cardType}</p>
                        <p><strong>Status:</strong> Pending Approval</p>
                        <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                        <p>Please log in to your administrative dashboard to review and process this application.</p>
                    `
                });

                // 4. Email Alert to User
                await transporter.sendMail({
                    from: `"${platformName} Support" <${adminEmail}>`,
                    to: userData.email,
                    subject: `Your ${cardType} Card Application is Pending`,
                    html: `
                        <p>Hello ${userData.firstname},</p>
                        <p>We have successfully received your application for a new <strong>${cardType}</strong> card.</p>
                        <p>Your request is currently under review by our team. We will notify you via email and your dashboard as soon as it is approved.</p>
                        <br/>
                        <p>Thank you for choosing ${platformName}.</p>
                    `
                });
            } catch (notificationErr) {
                console.warn("⚠️ Notification dispatch failed, but card was requested successfully:", notificationErr.message);
            }

            return res.status(200).json({
                success: true,
                message: "Card application submitted successfully."
            });
        }

        // -------------------------------------------------------------------------
        // TARGET ROUTE 2: VERIFY EXISTING PIN
        // -------------------------------------------------------------------------
        if (actionType === "verify_pin") {
            const inputPin = String(requestPayload.pin || "").trim();
            const storedPin = String(userData.pin || userData.card_pin || "").trim();

            if (!storedPin || storedPin !== inputPin) {
                const currentAttempts = (parseInt(userData.attempt2, 10) || 0) + 1;
                const remaining = 5 - currentAttempts;

                if (remaining <= 0) {
                    await supabase
                        .from("users")
                        .update({ restricted: true, activeuser: false, attempt2: 5 })
                        .eq("id", userData.id);

                    return res.status(403).json({
                        success: false,
                        restricted: true,
                        error: "Too many failed PIN attempts. Account locked."
                    });
                }

                await supabase
                    .from("users")
                    .update({ attempt2: currentAttempts })
                    .eq("id", userData.id);

                return res.status(400).json({
                    success: false,
                    error: `Incorrect PIN code. You have ${remaining} attempt(s) remaining.`
                });
            }

            await supabase
                .from("users")
                .update({ attempt2: 0 })
                .eq("id", userData.id);

            return res.status(200).json({
                success: true,
                message: "PIN verified successfully."
            });
        }

        // -------------------------------------------------------------------------
        // TARGET ROUTE 3: UPDATE / CONFIGURE PIN
        // -------------------------------------------------------------------------
        if (actionType === "pin" || actionType === "update_pin") {
            const currentPin = requestPayload.currentPin;
            const newPin = requestPayload.newPin || requestPayload.pin;

            if (!newPin) {
                return res.status(400).json({ success: false, error: "New PIN parameter is required." });
            }

            if (!/^[0-9]{4}$/.test(String(newPin).trim())) {
                return res.status(400).json({ success: false, error: "New PIN must be exactly 4 digits." });
            }

            const activePin = userData.pin || userData.card_pin;
            if (activePin && currentPin) {
                const storedPin = String(activePin || "").trim();
                const inputAuth = String(currentPin || "").trim();

                if (storedPin !== inputAuth) {
                    const currentPinAttempts = (parseInt(userData.attempt2, 10) || 0) + 1;
                    const remaining = 5 - currentPinAttempts;

                    if (remaining <= 0) {
                        await supabase
                            .from("users")
                            .update({ restricted: true, activeuser: false, attempt2: 5 })
                            .eq("id", userData.id);

                        return res.status(403).json({
                            success: false,
                            restricted: true,
                            error: "Too many failed PIN authorization attempts. Account locked."
                        });
                    }

                    await supabase
                        .from("users")
                        .update({ attempt2: currentPinAttempts })
                        .eq("id", userData.id);

                    return res.status(400).json({
                        success: false,
                        error: `Incorrect authorization PIN. You have ${remaining} attempt(s) remaining.`
                    });
                }
            }

            const { error: pinDbUpdateErr } = await supabase
                .from("users")
                .update({
                    pin: String(newPin).trim(),
                    card_pin: String(newPin).trim(),
                    attempt2: 0
                })
                .eq("id", userData.id);

            if (pinDbUpdateErr) {
                throw new Error("Database error updating PIN.");
            }

            return res.status(200).json({
                success: true,
                message: "PIN updated successfully."
            });
        }

        return res.status(400).json({ success: false, error: "Invalid action target specified." });

    } catch (err) {
        console.error("Fatal Error:", err.message);
        return res.status(500).json({ success: false, error: err.message || "An unexpected error occurred." });
    }
}