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

const executionAntiSpamCache = new Map();

function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    return signature.trim().charAt(0).toUpperCase() + signature.trim().slice(1);
}

export default async function handler(req, res) {
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
    // UNAUTHENTICATED ACTION BYPASS GATEWAYS (FORGOT PASSWORD PIPELINE)
    // ==========================================================================

    // 1. FORGOT PASSWORD REQUEST
    if (operationalSettingTarget === "forgot_password_request" && req.method === "POST") {
        const { email, signature } = requestPayload;
        if (!email || !signature) {
            return res.status(400).json({ success: false, error: "Email and signature are required." });
        }

        const cleanEmail = email.trim().toLowerCase();
        const dynamicPlatformName = formatPlatformName(signature);

        const { data: adminRecord, error: adminError } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email")
            .eq("signature", signature)
            .maybeSingle();

        if (adminError || !adminRecord) {
            return res.status(401).json({ success: false, error: "System configuration error. Please contact support." });
        }

        const { data: userRecord, error: userError } = await supabase
            .from("users")
            .select("uuid, email, restricted, activeuser, firstname")
            .eq("email", cleanEmail)
            .eq("signature", signature)
            .maybeSingle();

        if (userError || !userRecord) {
            return res.status(404).json({ success: false, error: "No account found with this email address." });
        }

        if (userRecord.restricted === true) {
            return res.status(403).json({ success: false, error: "Your account is locked due to security restrictions." });
        }

        const recoveryOTP = Math.floor(100000 + Math.random() * 900000).toString();

        const { error: updateError } = await supabase
            .from("users")
            .update({ otp: parseInt(recoveryOTP, 10), attempt: 0 })
            .eq("uuid", userRecord.uuid);

        if (updateError) {
            return res.status(500).json({ success: false, error: "Failed to update verification system." });
        }

        try {
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

            mailTransporter.sendMail({
                from: `"${dynamicPlatformName} Core Security" <${adminRecord.smtp_email}>`,
                to: userRecord.email,
                subject: `Password Recovery Code: ${recoveryOTP}`,
                html: `<h3>Your requested recovery verification code:</h3><br><h1 style="letter-spacing:4px; color:#0a698f;">${recoveryOTP}</h1>`
            }).catch(err => console.warn("⚠️ SMTP thread fail:", err.message));
        } catch (mErr) {
            console.warn("⚠️ Mail system init fault:", mErr.message);
        }

        return res.status(200).json({ success: true, user_id: userRecord.uuid });
    }

    // 2. FORGOT PASSWORD VERIFY OTP
    if ((operationalSettingTarget === "verify_password_otp" || requestPayload.action === "verify_password_otp") && req.method === "POST") {
        const { user_id, otp } = requestPayload;
        if (!user_id || !otp) {
            return res.status(400).json({ success: false, error: "Verification parameters are missing." });
        }

        const { data: userRecord, error: userError } = await supabase
            .from("users")
            .select("uuid, otp, restricted, activeuser, attempt")
            .eq("uuid", user_id)
            .maybeSingle();

        if (userError || !userRecord) {
            return res.status(404).json({ success: false, error: "User account not found." });
        }

        if (userRecord.restricted === true || userRecord.activeuser === false || (parseInt(userRecord.attempt, 10) >= 5)) {
            return res.status(403).json({
                success: false,
                restricted: true,
                error: "Account access restricted due to multiple failed verification attempts."
            });
        }

        const dbUserOtp = userRecord.otp ? String(userRecord.otp).trim() : "";
        const inputOtp = String(otp || "").trim();

        if (!dbUserOtp) {
            return res.status(400).json({ success: false, error: "No active verification code found for this account." });
        }

        if (dbUserOtp !== inputOtp) {
            const currentAttempt = (parseInt(userRecord.attempt, 10) || 0) + 1;
            const remaining = 5 - currentAttempt;

            if (remaining <= 0) {
                await supabase
                    .from("users")
                    .update({ restricted: true, activeuser: false, attempt: 5 })
                    .eq("uuid", userRecord.uuid);

                return res.status(403).json({
                    success: false,
                    restricted: true,
                    error: "Too many failed attempts. Your account has been restricted."
                });
            }

            await supabase
                .from("users")
                .update({ attempt: currentAttempt })
                .eq("uuid", userRecord.uuid);

            return res.status(401).json({
                success: false,
                restricted: false,
                error: `Incorrect verification code. You have ${remaining} attempt(s) remaining.`
            });
        }

        await supabase
            .from("users")
            .update({ otp: null, attempt: 0, restricted: false, activeuser: true })
            .eq("uuid", userRecord.uuid);

        return res.status(200).json({ success: true, message: "Verification successful." });
    }

    // 3. FORGOT PASSWORD COMMIT NEW PASSWORD
    if ((operationalSettingTarget === "commit_new_password" || requestPayload.action === "commit_new_password") && req.method === "POST") {
        const { user_id, password } = requestPayload;
        if (!user_id || !password) {
            return res.status(400).json({ success: false, error: "Invalid password reset payload." });
        }

        const { error: patchError } = await supabase
            .from("users")
            .update({
                password: String(password).trim(),
                attempt: 0,
                attempt2: 0,
                restricted: false,
                activeuser: true
            })
            .eq("uuid", user_id);

        if (patchError) return res.status(500).json({ success: false, error: "Database error updating password." });
        return res.status(200).json({ success: true, message: "Password reset successfully." });
    }

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

        // Cleaned up query (removed trailing comma) and included attempt counters
        const { data: userData, error: userError } = await supabase
            .from("users")
            .select("id, uuid, password, pin, email, activeuser, restricted, attempt, attempt2")
            .eq("uuid", decodedToken.uuid)
            .maybeSingle();

        if (userError || !userData) {
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

        const currentExecutionTimestamp = Date.now();
        const absoluteUserTrackerIdKey = userData.uuid;
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

        // -------------------------------------------------------------------------
        // TARGET ROUTE 1: UPDATE PASSWORD (WITH PERSISTENT ATTEMPT LOGIC)
        // -------------------------------------------------------------------------
        if (operationalSettingTarget === "password") {
            const currentPassword = requestPayload.currentPassword || requestPayload.oldPassword;
            const newPassword = requestPayload.newPassword;

            if (!currentPassword || !newPassword) {
                return res.status(400).json({ success: false, error: "Current password and new password are required." });
            }

            const storedPassword = String(userData.password || "").trim();
            const inputPassword = String(currentPassword || "").trim();

            if (storedPassword !== inputPassword) {
                const currentAttempts = (parseInt(userData.attempt, 10) || 0) + 1;
                const remaining = 5 - currentAttempts;

                if (remaining <= 0) {
                    await supabase
                        .from("users")
                        .update({ restricted: true, activeuser: false, attempt: 5 })
                        .eq("id", userData.id);

                    return res.status(403).json({
                        success: false,
                        restricted: true,
                        error: "Too many failed password attempts. Account locked."
                    });
                }

                await supabase
                    .from("users")
                    .update({ attempt: currentAttempts })
                    .eq("id", userData.id);

                return res.status(400).json({
                    success: false,
                    error: `Incorrect current password. You have ${remaining} attempt(s) remaining.`
                });
            }

            if (newPassword.length < 8) {
                return res.status(400).json({ success: false, error: "New password must be at least 8 characters long." });
            }

            const { error: passwordDbUpdateErr } = await supabase
                .from("users")
                .update({
                    password: String(newPassword).trim(),
                    attempt: 0
                })
                .eq("id", userData.id);

            if (passwordDbUpdateErr) throw new Error("Database error updating password.");

            const updatedUserToken = jwt.sign(
                { uuid: userData.uuid, email: userData.email },
                JWT_SECRET,
                { expiresIn: "7d" }
            );

            return res.status(200).json({
                success: true,
                message: "Password updated successfully.",
                token: updatedUserToken
            });
        }

        // -------------------------------------------------------------------------
        // TARGET ROUTE 2: UPDATE PIN (WITH PERSISTENT ATTEMPT LOGIC)
        // -------------------------------------------------------------------------
        if (operationalSettingTarget === "pin") {
            const currentPin = requestPayload.currentPin || requestPayload.password;
            const newPin = requestPayload.newPin || requestPayload.pin;

            if (!currentPin || !newPin) {
                return res.status(400).json({ success: false, error: "Current authentication key and new PIN are required." });
            }

            const storedPin = String(userData.pin || "").trim();
            const storedPassword = String(userData.password || "").trim();
            const inputAuth = String(currentPin || "").trim();

            if (storedPin !== inputAuth && storedPassword !== inputAuth) {
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
                    error: `Incorrect PIN or authorization password. You have ${remaining} attempt(s) remaining.`
                });
            }

            if (!/^[0-9]{4}$/.test(String(newPin).trim())) {
                return res.status(400).json({ success: false, error: "New PIN must be exactly 4 digits." });
            }

            const { error: pinDbUpdateErr } = await supabase
                .from("users")
                .update({
                    pin: String(newPin).trim(),
                    attempt2: 0
                })
                .eq("id", userData.id);

            if (pinDbUpdateErr) throw new Error("Database error updating PIN.");

            return res.status(200).json({ success: true, message: "PIN updated successfully." });
        }

        return res.status(400).json({ success: false, error: "Invalid action target specified." });

    } catch (err) {
        console.error("❌ Fatal Error:", err.message);
        return res.status(500).json({ success: false, error: err.message || "An unexpected error occurred." });
    }
}