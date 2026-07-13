import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

const executionAntiSpamCache = new Map();

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

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Credentials pointer missing." });
        }

        const token = authHeader.split(" ")[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ success: false, error: "Authentication footprint invalid or expired." });
        }

        // UPDATED: Added "last_password_change" field selection array to enforce stamp checks
        const { data: userData, error: userError } = await supabase
            .from("users")
            .select("id, uuid, password, pin, email, activeuser, image, last_password_change")
            .eq("uuid", decodedToken.uuid)
            .maybeSingle();

        if (userError || !userData) {
            return res.status(444).json({ success: false, error: "Identity link lookup anomaly." });
        }

        if (userData.activeuser === false) {
            return res.status(403).json({ success: false, activeuser: false, error: "Account suspended." });
        }

        // ==========================================================================
        // TOKEN STAMP SECURITY ALIGNMENT GATEWAY (ENFORCED FOR BOTH GET & POST)
        // ==========================================================================
        const tokenPasswordStamp = decodedToken.last_password_change;
        const databasePasswordStamp = userData.last_password_change;

        if (databasePasswordStamp && tokenPasswordStamp !== databasePasswordStamp) {
            return res.status(401).json({
                success: false,
                error: "Session Revoked: Your password has been changed on another active device terminal instance. Please re-authenticate."
            });
        }

        // -------------------------------------------------------------------------
        // METHOD: GET -> Return user layout attributes if requested
        // -------------------------------------------------------------------------
        if (req.method === "GET") {
            return res.status(200).json({
                success: true,
                email: userData.email || "",
                image: userData.image || null
            });
        }

        if (req.method !== "POST") {
            return res.status(405).json({ success: false, error: "Method blocked." });
        }

        // Anti-Spam Execution Prevention tracking gate
        const currentExecutionTimestamp = Date.now();
        const absoluteUserTrackerIdKey = userData.uuid;
        if (executionAntiSpamCache.has(absoluteUserTrackerIdKey)) {
            const previousLogTime = executionAntiSpamCache.get(absoluteUserTrackerIdKey);
            if (currentExecutionTimestamp - previousLogTime < 4000) {
                return res.status(429).json({
                    success: false,
                    error: "Security Alert: Processing operations too fast. Please rest 4 seconds before trying again."
                });
            }
        }
        executionAntiSpamCache.set(absoluteUserTrackerIdKey, currentExecutionTimestamp);

        const operationalSettingTarget = req.headers["x-setting-target"] || req.headers["X-Setting-Target"];
        const requestPayload = req.body || {};

        // -------------------------------------------------------------------------
        // TARGET ROUTE 1: UPDATE ACCOUNT PASSWORD WITH STAMP ROTATION
        // -------------------------------------------------------------------------
        if (operationalSettingTarget === "password") {
            const { currentPassword, newPassword } = requestPayload;
            if (!currentPassword || !newPassword) {
                return res.status(400).json({ success: false, error: "Missing verification criteria data vectors." });
            }

            if (userData.password !== currentPassword) {
                return res.status(400).json({ success: false, error: "Current account authorization password code is incorrect." });
            }

            if (newPassword.length < 8) {
                return res.status(400).json({ success: false, error: "Validation Fault: New key must meet minimum 8-character strings threshold." });
            }

            // Generate fresh security isolation token stamp right now
            const freshPasswordStamp = new Date().toISOString();

            const { error: passwordDbUpdateErr } = await supabase
                .from("users")
                .update({
                    password: newPassword,
                    last_password_change: freshPasswordStamp // Instantly flags down alternative active sessions
                })
                .eq("id", userData.id);

            if (passwordDbUpdateErr) throw new Error(passwordDbUpdateErr.message);

            // Re-sign active JWT token structure carrying the fresh timestamp so current device doesn't log out
            const updatedUserToken = jwt.sign(
                {
                    uuid: userData.uuid,
                    email: userData.email,
                    last_password_change: freshPasswordStamp
                },
                JWT_SECRET,
                { expiresIn: "7d" }
            );

            return res.status(200).json({
                success: true,
                message: "Security authorization keyphrase committed successfully.",
                token: updatedUserToken // Dispatched out the gate back to the frontend listener
            });
        }

        // -------------------------------------------------------------------------
        // TARGET ROUTE 2: UPDATE TRANSACTION PIN
        // -------------------------------------------------------------------------
        if (operationalSettingTarget === "pin") {
            const { currentPin, newPin } = requestPayload;
            if (!currentPin || !newPin) {
                return res.status(400).json({ success: false, error: "Input criteria structures required configuration missing." });
            }

            if (String(userData.pin) !== String(currentPin)) {
                return res.status(400).json({ success: false, error: "Current 4-Digit Operational Security PIN is invalid." });
            }

            if (!/^[0-9]{4}$/.test(newPin)) {
                return res.status(400).json({ success: false, error: "Formatting Exception: Pin parameters must stay confined inside 4-digit numbers rules." });
            }

            const { error: pinDbUpdateErr } = await supabase
                .from("users")
                .update({ pin: String(newPin) })
                .eq("id", userData.id);

            if (pinDbUpdateErr) throw new Error(pinDbUpdateErr.message);

            return res.status(200).json({ success: true, message: "Vault operational transaction clear token PIN updated cleanly." });
        }

        // -------------------------------------------------------------------------
        // TARGET ROUTE 3: MIGRATE ACCOUNT EMAIL
        // -------------------------------------------------------------------------
        if (operationalSettingTarget === "email") {
            const { newEmail, securityAuthPin } = requestPayload;
            if (!newEmail || !securityAuthPin) {
                return res.status(400).json({ success: false, error: "Data pipeline parameters missing attributes keys." });
            }

            if (String(userData.pin) !== String(securityAuthPin)) {
                return res.status(400).json({ success: false, error: "PIN identity verification failure: Authorization denied." });
            }

            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
                return res.status(400).json({ success: false, error: "Email formatting check rules anomaly validation rejected." });
            }

            const { error: emailDbUpdateErr } = await supabase
                .from("users")
                .update({ email: newEmail })
                .eq("id", userData.id);

            if (emailDbUpdateErr) throw new Error(emailDbUpdateErr.message);

            return res.status(200).json({ success: true, message: "Primary alerting notification mail node migrated successfully." });
        }

        return res.status(400).json({ success: false, error: "Target operational execution routing command undefined." });

    } catch (criticalCrashLog) {
        console.error("❌ System Settings Controller Base Fatal Error:", criticalCrashLog.message);
        return res.status(500).json({ success: false, error: criticalCrashLog.message });
    }
}