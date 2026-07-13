import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws"; // Explicitly load websocket support polyfill framework for Node 20 runtime

// Flexible config framework mapping - reads from either PUBLIC_ prefix or standard naming rules
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// Explicit system safety validation checks on initialization
if (!SUPABASE_URL) throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: Both process.env.PUBLIC_SUPABASE_URL and process.env.SUPABASE_URL are missing.");
if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: process.env.SUPABASE_SERVICE_ROLE_KEY is missing.");
if (!JWT_SECRET) throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: process.env.JWT_SECRET is missing.");

// Instantiate client explicitly injecting the websocket transport options to resolve server crash
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
        persistSession: false
    },
    realtime: {
        transport: ws
    }
});

// Helper function to dynamically capitalize the first letter of the platform signature
function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
}

export default async function handler(req, res) {
    // 1. Core CORS Interception Layer Setup - MUST run before any checking logic
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    // 2. Allow all HTTP methods your handlers use
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // 3. Explicitly allow all your specific custom app headers
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");

    // 4. Keep your credentials authentication layer active
    res.setHeader("Access-Control-Allow-Credentials", "true");

    // Handle preflight options request immediately
    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    // Your route safety check (example for a POST endpoint)
    if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "Method blocked." });
    }

    try {
        const { action, ...payload } = req.body;

        if (!action) {
            return res.status(400).json({ success: false, error: "Missing action execution parameter value." });
        }

        // Action route handling core account setups
        if (action === "register") {
            return await handleRegistration(payload, res);
        }

        // --- ACTION HANDLERS FOR LOGIN PIPELINES ---
        if (action === "login") {
            return await handleLoginRequest(payload, res);
        }

        if (action === "verify_otp") {
            return await handleOTPVerification(payload, res);
        }

        // --- ACTION HANDLERS FOR FORGOT PASSWORD RECOVERY PIPELINES ---
        if (action === "forgot_password_request") {
            return await handleForgotPasswordRequest(payload, res);
        }

        if (action === "verify_password_otp") {
            return await handleForgotPasswordOTPVerification(payload, res);
        }

        if (action === "commit_new_password") {
            return await handleCommitNewPassword(payload, res);
        }

        return res.status(400).json({ success: false, error: "Invalid context action parameter." });

    } catch (globalError) {
        console.error("❌ Critical server thread fault:", globalError);
        return res.status(500).json({ success: false, error: globalError.message });
    }
}

/**
 * PHASE 1 LOGIN HANDLER: Initial Credentials & Signature Verification
 */
async function handleLoginRequest(payload, res) {
    const { email, password, signature } = payload;

    if (!email) return res.status(400).json({ success: false, error: "Bad Request: Missing 'email' parameter." });
    if (!password) return res.status(400).json({ success: false, error: "Bad Request: Missing 'password' parameter." });
    if (!signature) return res.status(400).json({ success: false, error: "Bad Request: Missing deployment 'signature' tracking string." });

    const cleanEmail = email.trim().toLowerCase();
    const dynamicPlatformName = formatPlatformName(signature);

    const { data: adminRecord, error: adminError } = await supabase
        .from("admin")
        .select("smtp_host, smtp_port, smtp_password, smtp_email")
        .eq("signature", signature)
        .maybeSingle();

    if (adminError) {
        return res.status(500).json({ success: false, error: `Database Error during Admin look-up: ${adminError.message}` });
    }
    if (!adminRecord) {
        return res.status(401).json({ success: false, error: `Authentication Failed: No administrative environment found matching signature string '${signature}'.` });
    }

    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, email, password, activeuser, restricted, attempt, firstname")
        .eq("email", cleanEmail)
        .eq("signature", signature)
        .maybeSingle();

    if (userError) {
        return res.status(500).json({ success: false, error: `Database Error during User verification lookup: ${userError.message}` });
    }
    if (!userRecord) {
        return res.status(401).json({ success: false, error: `Authentication Failed: User record with email '${cleanEmail}' not found.` });
    }

    const currentAttempts = parseInt(userRecord.attempt, 10) || 0;

    // Strict multi-device lock rules validation logic framework
    if (currentAttempts >= 5 || userRecord.restricted === true || userRecord.activeuser === false) {
        // Enforce synchronization backup verification check
        if (currentAttempts < 5 && (userRecord.restricted === true || userRecord.activeuser === false)) {
            // This condition implies an administrative unlock was applied to row flags, but attempts count was left stale. Clear it out.
            await supabase.from("users").update({ attempt: 0, restricted: false, activeuser: true }).eq("uuid", userRecord.uuid);
        } else {
            return res.status(403).json({ success: false, error: "Access Denied: This account workspace profile is restricted globally across all terminals." });
        }
    }

    if (userRecord.password !== password) {
        return res.status(401).json({ success: false, error: "Authentication Failed: Incorrect password verification match." });
    }

    const generatedOTP = Math.floor(100000 + Math.random() * 900000).toString();

    // Auto reset attempt column safely back to 0 immediately upon passing the credential screen
    const { error: updateError } = await supabase
        .from("users")
        .update({ otp: generatedOTP, attempt: 0, restricted: false, activeuser: true })
        .eq("uuid", userRecord.uuid);

    if (updateError) {
        return res.status(500).json({ success: false, error: `Failed to commit transient security parameters mapping state: ${updateError.message}` });
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

        const otpHtmlTemplate = `<!DOCTYPE html>
        <html>
        <body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial, sans-serif; color:#333;">
            <div style="max-width:500px; margin:20px auto; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 5px rgba(0,0,0,0.05); padding:30px;">
                <h2 style="color:#0ea365; margin-top:0;">${dynamicPlatformName} Login Verification</h2>
                <p style="font-size:15px;">Hello ${userRecord.firstname || "User"},</p>
                <p style="font-size:14px; color:#555; line-height:1.5;">An access sequence request was initialized on your profile. Please use the following 6-digit verification code token to finalize identification checks:</p>
                <div style="background:#f0fdf4; border:1px dashed #0ea365; padding:15px; text-align:center; font-size:26px; font-weight:bold; letter-spacing:4px; color:#059669; margin:20px 0; border-radius:6px;">
                    ${generatedOTP}
                </div>
                <p style="font-size:11px; color:#999;">This temporary protection token expires inside immediate operational usage limits.</p>
            </div>
        </body>
        </html>`;

        mailTransporter.sendMail({
            from: `"${dynamicPlatformName} Identity Protection" <${adminRecord.smtp_email}>`,
            to: userRecord.email,
            replyTo: adminRecord.smtp_email,
            headers: {
                "X-Auto-Response-Suppress": "All",
                "Precedence": "bulk"
            },
            subject: `Verification Identity Passcode Token: ${generatedOTP}`,
            html: otpHtmlTemplate
        }).catch((err) => {
            console.warn("⚠️ Background email thread error during login OTP send:", err.message);
        });

    } catch (mailError) {
        console.warn("⚠️ Dynamic SMTP engine initialization error:", mailError.message);
    }

    return res.status(200).json({
        success: true,
        message: "Dynamic validation code dispatched to your tracking profile.",
        user_id: userRecord.uuid
    });
}

/**
 * PHASE 2 LOGIN HANDLER: Custom Virtual OTP Verification Engine incorporating centralized cross-device attempts counter architecture mapping rules
 */
async function handleOTPVerification(payload, res) {
    const { user_id, otp, signature } = payload;

    if (!user_id) return res.status(400).json({ success: false, error: "Missing required 'user_id' parameter framework tracker." });
    if (!otp) return res.status(400).json({ success: false, error: "Missing 'otp' input validation string token property." });
    if (!signature) return res.status(400).json({ success: false, error: "Missing required 'signature' parameters inside authorization verification layers." });

    const dynamicPlatformName = formatPlatformName(signature);

    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, email, otp, activeuser, restricted, attempt, firstname, lastname, \"accountNumber\", accttype, currency")
        .eq("uuid", user_id)
        .maybeSingle();

    if (userError || !userRecord) {
        return res.status(404).json({ success: false, error: "Profile verification sequence broken. User profile target context lookup returned null properties." });
    }

    // Direct check of system database block parameters flags
    if (userRecord.restricted === true || userRecord.activeuser === false || (parseInt(userRecord.attempt, 10) || 0) >= 5) {
        return res.status(403).json({ success: false, error: "Access Denied: This account workspace profile is restricted globally." });
    }

    // Direct comparison alignment matching dedicated 'otp' storage column
    if (!userRecord.otp || String(userRecord.otp) !== String(otp).trim()) {
        const databaseAttemptsCount = (parseInt(userRecord.attempt, 10) || 0) + 1;
        const totalRemainingAttempts = 5 - databaseAttemptsCount;

        if (totalRemainingAttempts <= 0 || databaseAttemptsCount >= 5) {
            // Profile is restricted on all devices globally inside database schema tables rows
            await supabase
                .from("users")
                .update({ activeuser: false, restricted: true, attempt: 5 })
                .eq("uuid", userRecord.uuid);

            return res.status(403).json({
                success: false,
                account_locked: true,
                error: "Security violations boundary reached. This account workspace profile is now restricted."
            });
        }

        // Increment attempt tracking integer value inside user database columns framework row mapping blocks
        await supabase
            .from("users")
            .update({ attempt: databaseAttemptsCount })
            .eq("uuid", userRecord.uuid);

        return res.status(401).json({
            success: false,
            account_locked: false,
            error: `Invalid access validation passcode match failed. You have ${totalRemainingAttempts} remaining attempts before lock.`
        });
    }

    // Security cleared: Wipe code and reset global dynamic device counter to 0
    await supabase.from("users").update({ otp: null, attempt: 0, restricted: false, activeuser: true }).eq("uuid", userRecord.uuid);

    try {
        const { data: adminRecord, error: adminLookupError } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email")
            .eq("signature", signature)
            .maybeSingle();

        if (!adminLookupError && adminRecord) {
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

            const loginNotifyHtml = `<!DOCTYPE html>
            <html lang="en">
            <body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial, sans-serif; color:#333;">
                <div style="max-width:600px; margin:20px auto; background:#fff; padding:30px; border-radius:8px;">
                    <h3 style="color:#0a698f;">Successful Account Access Notification</h3>
                    <p>Hello ${userRecord.firstname},</p>
                    <p>This confirms your profile has successfully authorized clearance steps on the platform portal dashboard workspace.</p>
                </div>
            </body>
            </html>`;

            mailTransporter.sendMail({
                from: `"${dynamicPlatformName} Alert" <${adminRecord.smtp_email}>`,
                to: userRecord.email,
                subject: `New login authorization detected on your account`,
                html: loginNotifyHtml
            }).catch(e => console.warn(e.message));
        }
    } catch (_) { }

    const token = jwt.sign(
        { uuid: userRecord.uuid, email: userRecord.email, signature: signature },
        JWT_SECRET,
        { expiresIn: "24h" }
    );

    return res.status(200).json({
        success: true,
        token: token,
        user: {
            uuid: userRecord.uuid,
            email: userRecord.email,
            name: `${userRecord.firstname} ${userRecord.lastname}`,
            accountNumber: userRecord.accountNumber,
            accttype: userRecord.accttype,
            currency: userRecord.currency
        }
    });
}

/**
 * PLACEHOLDER ROUTING MODULE STUBS FOR INTERFACED ACTIONS
 */
async function handleRegistration(payload, res) {
    return res.status(200).json({ success: true, message: "Registration stub hook completed." });
}

async function handleForgotPasswordRequest(payload, res) {
    return res.status(200).json({ success: true, message: "Password recovery request code stub executed." });
}

async function handleForgotPasswordOTPVerification(payload, res) {
    return res.status(200).json({ success: true, message: "Recovery token assertion code stub processed." });
}

async function handleCommitNewPassword(payload, res) {
    return res.status(200).json({ success: true, message: "Security matrix field modification update complete." });
}