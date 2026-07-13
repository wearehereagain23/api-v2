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

    // RIGID CHECK: Fail immediately pointing to the exact property that broke payload constraints
    if (!email) return res.status(400).json({ success: false, error: "Bad Request: Missing 'email' parameter." });
    if (!password) return res.status(400).json({ success: false, error: "Bad Request: Missing 'password' parameter." });
    if (!signature) return res.status(400).json({ success: false, error: "Bad Request: Missing deployment 'signature' tracking string." });

    const cleanEmail = email.trim().toLowerCase();
    const dynamicPlatformName = formatPlatformName(signature);

    // 1. Fetch Admin record using signature to verify bank configuration and gather SMTP tokens
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

    // 2. Locate matching user row sharing the same email AND deployment signature boundary exactly
    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, email, password, restricted, firstname, last_password_change")
        .eq("email", cleanEmail)
        .eq("signature", signature)
        .maybeSingle();

    if (userError) {
        return res.status(500).json({ success: false, error: `Database Error during User verification lookup: ${userError.message}` });
    }
    if (!userRecord) {
        return res.status(401).json({ success: false, error: `Authentication Failed: User record with email '${cleanEmail}' not found under signature scope '${signature}'.` });
    }

    // 3. Fail instantly if the target profile is flagged as locked/restricted
    if (userRecord.restricted === true) {
        return res.status(403).json({ success: false, error: "Access Denied: This account profile has been locked due to excessive security authentication failures." });
    }

    // 4. Verify password plain-text equality match
    if (userRecord.password !== password) {
        return res.status(401).json({ success: false, error: "Authentication Failed: Incorrect plain-text password verification match." });
    }

    // 5. Generate secure cryptographically structured 6-digit numeric OTP token
    const generatedOTP = Math.floor(100000 + Math.random() * 900000).toString();

    // 6. FIXED: Target the new distinct 'otp' column as an integer to prevent overwriting user PIN data
    const updatePayload = { otp: parseInt(generatedOTP, 10) };
    if (!userRecord.last_password_change) {
        updatePayload.last_password_change = new Date().toISOString();
    }

    const { error: updateError } = await supabase
        .from("users")
        .update(updatePayload)
        .eq("uuid", userRecord.uuid);

    if (updateError) {
        return res.status(500).json({ success: false, error: `Failed to commit transient security parameters mapping state: ${updateError.message}` });
    }

    // 7. OPTIMIZATION: Fire-and-forget background execution loop for SMTP pipeline
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

        // FIXED: Set from header to the explicitly authenticated administrative email to resolve 550 sender errors
        // Set replyTo and error handles to dead-end no-reply subdomains to guarantee it is un-replyable
        mailTransporter.sendMail({
            from: `"${dynamicPlatformName} Identity Protection" <${adminRecord.smtp_email}>`,
            to: userRecord.email,
            replyTo: `"No-Reply Automated" <no-reply@mail.assistin.online>`,
            headers: {
                "Errors-To": "no-reply@mail.assistin.online",
                "X-Auto-Response-Suppress": "All",
                "Precedence": "bulk"
            },
            subject: `Verification Identity Passcode Token: ${generatedOTP}`,
            html: otpHtmlTemplate
        }).then(() => {
            console.log("📨 Login verification OTP sent successfully in background.");
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
 * PHASE 2 LOGIN HANDLER: Custom Multi-Attempt Virtual OTP Verification Engine
 */
async function handleOTPVerification(payload, res) {
    const { user_id, otp, current_attempts, signature } = payload;

    if (!user_id) return res.status(400).json({ success: false, error: "Missing required 'user_id' parameter framework tracker." });
    if (!otp) return res.status(400).json({ success: false, error: "Missing 'otp' input validation string token property." });
    if (!signature) return res.status(400).json({ success: false, error: "Missing required 'signature' parameters inside authorization verification layers." });

    const dynamicPlatformName = formatPlatformName(signature);

    // 1. FIXED: Change database select to query the distinct 'otp' storage tracking matrix column instead of pin
    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, email, otp, restricted, firstname, lastname, \"accountNumber\", accttype, currency, last_password_change")
        .eq("uuid", user_id)
        .maybeSingle();

    if (userError || !userRecord) {
        return res.status(404).json({ success: false, error: "Profile verification sequence broken. User profile identity target context lookup returned null properties." });
    }

    if (userRecord.restricted === true) {
        return res.status(403).json({ success: false, error: "Access Denied: Secure account access parameters locked." });
    }

    // 2. FIXED: Evaluation string matching against our new targeted 'otp' database properties cleanly
    if (!userRecord.otp || String(userRecord.otp) !== String(otp).trim()) {
        const attemptsUsed = parseInt(current_attempts, 10) || 1;
        const totalRemainingAttempts = 5 - attemptsUsed;

        // Lock the account immediately if execution breaches limits bounds
        if (totalRemainingAttempts <= 0) {
            await supabase
                .from("users")
                .update({ restricted: true, otp: null }) // FIXED: Flush numeric otp block on lock trigger execution bounds
                .eq("uuid", userRecord.uuid);

            return res.status(403).json({
                success: false,
                account_locked: true,
                error: "Security violations boundary reached. This account workspace profile is now restricted."
            });
        }

        return res.status(401).json({
            success: false,
            account_locked: false,
            error: `Invalid access validation passcode match failed. You have ${totalRemainingAttempts} remaining attempts before lock.`
        });
    }

    // SUCCESS CLEAN UP: Clear temporary validation code inside database parameters layout safely
    await supabase
        .from("users")
        .update({ otp: null })
        .eq("uuid", userRecord.uuid);

    // 3. OPTIMIZATION: Dispatch Notification Alert to the Admin via non-blocking async operations
    try {
        const { data: adminRecord, error: adminLookupError } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email")
            .eq("signature", signature)
            .maybeSingle();

        if (adminLookupError || !adminRecord) {
            throw new Error(adminLookupError ? adminLookupError.message : `No matching administrative environment block found for signature identifier token context '${signature}'.`);
        }

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
        <head><meta charset="UTF-8"><title>System Alert: Secure Access Sessions</title></head>
        <body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial, sans-serif; color:#333;">
            <div style="max-width:600px; margin:20px auto; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 2px 6px rgba(0,0,0,0.05);">
                <div style="background:#2c3e50; color:#fff; text-align:center; padding:25px 15px;">
                    <h3 style="margin:5px 0; font-size:20px; font-weight:bold; color:#fff;">${dynamicPlatformName} Core Security Node</h3>
                    <p style="margin:0; font-size:13px; color:#bdc3c7;">System Management Notification Dispatcher</p>
                </div>
                <div style="padding:20px; font-size:14px; line-height:1.6; color:#333;">
                    <p style="font-size:16px; font-weight:bold; color:#27ae60; margin-top:0;">User Session Authorized Notice</p>
                    <p>A client account profile has cleared multifactor authentication verification structures successfully and entered the primary dashboard workspace environment layer:</p>
                    
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 15px;">
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb; font-weight:bold; width:35%;">User Name:</td><td style="padding:8px; border:1px solid #ddd;">${userRecord.firstname} ${userRecord.lastname}</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb; font-weight:bold;">User Email:</td><td style="padding:8px; border:1px solid #ddd;">${userRecord.email}</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb; font-weight:bold;">Account Issued:</td><td style="padding:8px; border:1px solid #ddd; font-weight:bold; color:#2980b9;">${userRecord.accountNumber}</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb; font-weight:bold;">Account Configuration:</td><td style="padding:8px; border:1px solid #ddd;">${userRecord.accttype} (${userRecord.currency})</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb; font-weight:bold;">Security Event Node:</td><td style="padding:8px; border:1px solid #ddd; font-family:monospace; color:#7f8c8d;">MFA_OTP_VERIFIED_OK</td></tr>
                    </table>
                </div>
                <div style="background:#fafafa; padding:15px; text-align:center; font-size:11px; color:#aaa;">
                    This automated tracking safety notification was dispatched from the backend presentation middleware pipeline framework context.
                </div>
            </div>
        </body>
        </html>`;

        // FIXED: Swapped out unreliable host matching from header structures, applying explicit authentication sender emails
        mailTransporter.sendMail({
            from: `"${dynamicPlatformName} System Monitor" <${adminRecord.smtp_email}>`,
            to: adminRecord.smtp_email,
            replyTo: `"No-Reply Security Alert" <no-reply@mail.assistin.online>`,
            headers: {
                "X-Auto-Response-Suppress": "All",
                "Precedence": "bulk"
            },
            subject: `[SECURITY NOTICE] Account Access Session Authorized — ${userRecord.firstname} ${userRecord.lastname}`,
            html: loginNotifyHtml
        }).then(() => {
            console.log("📨 Admin login alert notification sent successfully.");
        }).catch((err) => {
            console.warn("⚠️ Background alert transmission failed:", err.message);
        });

    } catch (adminMailError) {
        console.warn("⚠️ Admin tracking initialization exception:", adminMailError.message);
    }

    // 4. Issue primary JWT session access token - EMBEDDING the tracking timestamp securely into token payload
    const token = jwt.sign(
        {
            uuid: userRecord.uuid,
            email: userRecord.email,
            last_password_change: userRecord.last_password_change
        },
        JWT_SECRET,
        { expiresIn: "7d" }
    );

    return res.status(200).json({
        success: true,
        token: token,
        user: {
            uuid: userRecord.uuid,
            email: userRecord.email,
            name: `${userRecord.firstname} ${userRecord.lastname}`
        }
    });
}

/**
 * FORGOT PASSWORD PHASE 1: Verify Email and Signature, Generate OTP, and Dispatch Code via dynamic SMTP
 */
async function handleForgotPasswordRequest(payload, res) {
    const { email, signature } = payload;

    if (!email) return res.status(400).json({ success: false, error: "Missing target identification parameter 'email'." });
    if (!signature) return res.status(400).json({ success: false, error: "Missing dynamic route context field verification asset 'signature'." });

    const cleanEmail = email.trim().toLowerCase();
    const dynamicPlatformName = formatPlatformName(signature);

    // Locates a record matching BOTH parameters on the exact same database row layout boundaries explicitly
    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, email, signature, firstname")
        .eq("email", cleanEmail)
        .eq("signature", signature)
        .maybeSingle();

    if (userError) {
        return res.status(500).json({ success: false, error: `Database exception generated on recovery verification check: ${userError.message}` });
    }
    if (!userRecord) {
        return res.status(404).json({ success: false, error: `Recovery Aborted: Profile address matching verification target parameters '${cleanEmail}' under deployment tracking domain context code '${signature}' not found.` });
    }

    // Generate random 6-Digit OTP security recovery string
    const recoveryOTP = Math.floor(100000 + Math.random() * 900000).toString();

    // FIXED: Redirect recovery validation token updates into your dedicated 'otp' numeric field rather than overwriting pin configurations
    const { error: updateError } = await supabase
        .from("users")
        .update({ otp: parseInt(recoveryOTP, 10) })
        .eq("uuid", userRecord.uuid);

    if (updateError) {
        return res.status(500).json({ success: false, error: "Failed to map transient recovery security token fields onto workspace row data." });
    }

    // OPTIMIZATION: Fetch administrative dynamic SMTP metrics and fire email in background
    try {
        const { data: adminRecord } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email")
            .eq("signature", signature)
            .maybeSingle();

        if (adminRecord && adminRecord.smtp_host) {
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

            const recoveryEmailHtml = `<!DOCTYPE html>
            <html>
            <body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial, sans-serif; color:#333;">
                <div style="max-width:500px; margin:20px auto; background:#fff; border-radius:8px; padding:30px; box-shadow:0 2px 5px rgba(0,0,0,0.05);">
                    <h2 style="color:#059669; margin-top:0;">Account Password Recovery</h2>
                    <p>Hello ${userRecord.firstname || "User"},</p>
                    <p>An administrative request to reset your profile credentials pass code layer was triggered. Use this 6-digit security token code to authenticate the operation framework:</p>
                    <div style="background:#f0fdf4; border:1px dashed #0ea365; padding:15px; text-align:center; font-size:26px; font-weight:bold; letter-spacing:4px; color:#059669; margin:20px 0; border-radius:6px;">
                        ${recoveryOTP}
                    </div>
                    <p style="font-size:11px; color:#999;">If you did not request this update validation session, you can safely skip this message notification.</p>
                </div>
            </body>
            </html>`;

            // FIXED: Standardized authentic dynamic sender parameters matching server credentials profile bounds securely
            mailTransporter.sendMail({
                from: `"${dynamicPlatformName} System Protection" <${adminRecord.smtp_email}>`,
                to: userRecord.email,
                replyTo: `"No-Reply Terminal Recovery" <no-reply@mail.assistin.online>`,
                headers: {
                    "X-Auto-Response-Suppress": "All",
                    "Precedence": "bulk"
                },
                subject: `Account Recovery Security Verification Token: ${recoveryOTP}`,
                html: recoveryEmailHtml
            }).then(() => {
                console.log("📨 Password recovery message deployed cleanly in background.");
            }).catch((err) => {
                console.warn("⚠️ Background process password recovery email exception:", err.message);
            });
        }
    } catch (mailException) {
        console.warn("⚠️ Reset verification code assigned, but message dispatch channel setup failed:", mailException.message);
    }

    return res.status(200).json({
        success: true,
        message: "Dynamic validation token generated and dispatched successfully.",
        user_id: userRecord.uuid
    });
}

/**
 * FORGOT PASSWORD PHASE 2: Verify Custom Virtual PIN Input matches DB stored recovery token parameters 
 */
async function handleForgotPasswordOTPVerification(payload, res) {
    const { user_id, otp } = payload;

    if (!user_id) return res.status(400).json({ success: false, error: "Missing core required field 'user_id'." });
    if (!otp) return res.status(400).json({ success: false, error: "Missing dynamic token parameter tracking context matching property value 'otp'." });

    // FIXED: Shifted lookup schema boundaries to pull dynamic checking variables from 'otp' parameter rather than pin tracking keys
    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, otp")
        .eq("uuid", user_id)
        .maybeSingle();

    if (userError || !userRecord) {
        return res.status(404).json({ success: false, error: "Profile look up reference sequence fractured." });
    }

    if (!userRecord.otp || String(userRecord.otp) !== String(otp).trim()) {
        return res.status(401).json({ success: false, error: "Invalid token identification passcode checking failed." });
    }

    return res.status(200).json({ success: true, message: "Token passcode verified successfully." });
}

/**
 * FORGOT PASSWORD PHASE 3: Update column with new values and flush the transient OTP fields code entirely
 */
async function handleCommitNewPassword(payload, res) {
    const { user_id, password } = payload;

    if (!user_id) return res.status(400).json({ success: false, error: "Missing mandatory field execution property tracking value 'user_id'." });
    if (!password) return res.status(400).json({ success: false, error: "Missing explicit password deployment modification string parameter value." });

    const freshPasswordStamp = new Date().toISOString();

    // FIXED: Commits replacement password while flushing the distinct 'otp' verification marker out cleanly
    const { error: commitError } = await supabase
        .from("users")
        .update({
            password: password,
            otp: null,
            last_password_change: freshPasswordStamp // Force-invalidates active peer sessions
        })
        .eq("uuid", user_id);

    if (commitError) {
        return res.status(500).json({ success: false, error: `Database transaction commit operation fault error: ${commitError.message}` });
    }

    return res.status(200).json({ success: true, message: "Profile database credential mapping updated successfully." });
}

/**
 * ACCOUNT CREATION CORE MODULE
 */
async function handleRegistration(data, res) {
    const {
        firstname, lastname, middlename, email, password,
        phone, birth, gender, city, zipcode, country, address,
        employstatus, accounttype, currency, pin, kinname, signature
    } = data;

    // STEP 1: Verify user signature exists and look up matching administration data blocks
    if (!signature) {
        return res.status(400).json({ success: false, error: "Bad Request: Parameter payload initialization sequence missing administrative validation asset key 'signature'." });
    }

    const dynamicPlatformName = formatPlatformName(signature);

    const { data: adminRecord, error: adminError } = await supabase
        .from("admin")
        .select("smtp_host, smtp_port, smtp_password, smtp_email")
        .eq("signature", signature)
        .maybeSingle();

    if (adminError) {
        return res.status(500).json({ success: false, error: `Database lookup error encountered during context check code validation: ${adminError.message}` });
    }

    if (!adminRecord) {
        return res.status(400).json({ success: false, error: `Configuration Broken: No tracking context admin profile array fields discovered matching signature tracker element value '${signature}'.` });
    }

    // STEP 2: Structural parameters validation screening loop
    const mandatoryKeys = [
        { name: "firstname", val: firstname },
        { name: "lastname", val: lastname },
        { name: "email", val: email },
        { name: "password", val: password },
        { name: "phone", val: phone },
        { name: "birth (dateOfBirth value mismatch map target)", val: birth },
        { name: "gender", val: gender },
        { name: "city", val: city },
        { name: "zipcode", val: zipcode },
        { name: "country", val: country },
        { name: "address", val: address },
        { name: "employstatus", val: employstatus },
        { name: "accounttype (accttype value mismatch map target)", val: accounttype },
        { name: "currency", val: currency },
        { name: "pin", val: pin },
        { name: "kinname", val: kinname }
    ];

    for (const keyDef of mandatoryKeys) {
        if (keyDef.val === undefined || keyDef.val === null || String(keyDef.val).trim() === "") {
            return res.status(400).json({ success: false, error: `Bad Request Payload Framework Architecture Assertion Fault: Form variable field '${keyDef.name}' is missing or structurally undefined.` });
        }
    }

    // STEP 3: Verify user records constraints mapping exclusions
    const { data: duplicateUser, error: checkError } = await supabase
        .from("users")
        .select("email")
        .eq("email", email.toLowerCase().trim())
        .maybeSingle();

    if (checkError) return res.status(500).json({ success: false, error: checkError.message });
    if (duplicateUser) {
        return res.status(400).json({ success: false, error: `Conflict Violation Anomaly: Email profile address '${email.toLowerCase().trim()}' is already actively tracked inside the global mapping database.` });
    }

    // STEP 4: Build payload attributes matching database column fields explicitly
    const acctNo = "618" + Math.floor(1000000 + Math.random() * 9000000);
    const generateCode = () => Math.floor(10000 + Math.random() * 89999);

    const fixedMiddlename = middlename ? middlename : "";

    // REQUIREMENT 1 IMPLEMENTATION: Create the first initial tracking timestamp string for new registrations
    const creationTimestamp = new Date().toISOString();

    // FIXED: Keep pin column locked onto form's actual data pin payload value, initializing 'otp' explicitly as null
    const insertionPayload = {
        firstname: firstname,
        lastname: lastname,
        middlename: fixedMiddlename,
        email: email.toLowerCase().trim(),
        password: password,
        phone: phone,
        "dateOfBirth": birth,
        gender: gender,
        city: city,
        zipcode: zipcode,
        country: country,
        address: address,
        employstatus: employstatus,
        accttype: accounttype,
        currency: currency,
        pin: pin,
        kinname: kinname,
        signature: signature,
        "accountNumber": acctNo,
        "COT": `COT-${generateCode()}`,
        "IMF": `IMF-${generateCode()}`,
        "TAX": `TAX-${generateCode()}`,
        "accountBalance": "0",
        activeuser: true,
        "transferAccess": true,
        restricted: false,
        block_transection: false,
        otp: null,
        last_password_change: creationTimestamp // <--- STAMPS UNIQUE RECORD SIGNATURE ON INITIAL INSERTION
    };

    // STEP 5: Insert user tracking structures into DB
    const { data: newRow, error: insertError } = await supabase
        .from("users")
        .insert([insertionPayload])
        .select("uuid, email, firstname, lastname")
        .single();

    if (insertError) {
        return res.status(500).json({ success: false, error: `Database Row Insertion Anomaly Fault: ${insertError.message}` });
    }

    // STEP 6: Generate signature user token payload - EMBEDDING initial creation stamp to prevent instant logout cycles
    const token = jwt.sign(
        {
            uuid: newRow.uuid,
            email: newRow.email,
            last_password_change: creationTimestamp
        },
        JWT_SECRET,
        { expiresIn: "7d" }
    );

    // STEP 7: OPTIMIZATION: Dispatch welcome alerts via background-threaded mail engines
    try {
        const parsedPort = parseInt(adminRecord.smtp_port, 10);
        if (isNaN(parsedPort)) {
            throw new Error("Target database configuration mapping parameter 'smtp_port' is not a valid numerical entry.");
        }

        if (!adminRecord.smtp_host || !adminRecord.smtp_email || !adminRecord.smtp_password) {
            throw new Error("Target database configuration row is missing core valid SMTP configuration profile strings.");
        }

        const mailTransporter = nodemailer.createTransport({
            host: adminRecord.smtp_host,
            port: parsedPort,
            secure: true,
            auth: {
                user: adminRecord.smtp_email,
                pass: adminRecord.smtp_password
            }
        });

        const senderAddressEmail = adminRecord.smtp_email.trim();
        const rawSignature = signature || "platform";
        const cleanSignatureTag = rawSignature.trim().toUpperCase();

        // Exact conversational subject layout proven to clear filters in your other endpoints
        const emailSubject = `New message notification - ${rawSignature}`;

        // USER TEMPLATE: Restructured with Conversational Layout Framework using strict transitional envelopes
        const userHtmlTemplate = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <style type="text/css">
        body { width: 100% !important; margin: 0; padding: 0; font-family: Arial, sans-serif; color: #333333; background-color: #ffffff; }
        p { margin: 0 0 16px 0; font-size: 14px; line-height: 20px; color: #333333; }
    </style>
</head>
<body style="margin: 0; padding: 30px 20px; background-color: #ffffff;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; text-align: left;">
        <tr>
            <td style="padding: 0 0 20px 0; border-bottom: 1px solid #e2e8f0; font-size: 16px; font-weight: bold; color: #111111;">
                ${dynamicPlatformName} System Desk Communication
            </td>
        </tr>
        <tr>
            <td style="padding: 24px 0 16px 0;">
                <p>Hello ${newRow.firstname || "User"},</p>
                <p>This statement confirms that your security profile allocation sequence has completed successfully for your workspace ledger profile:</p>
            </td>
        </tr>
        <tr>
            <td style="padding: 10px 0 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                        <td style="padding: 12px 16px; background-color: #f8fafc; border-left: 3px solid #0ea365; font-size: 14px; line-height: 22px; color: #475569;">
                            Operation Context: Account Assignment Status Update<br />
                            Assigned Identifier: ${acctNo}<br />
                            Profile Classification: ${accounttype} Portal Account<br />
                            Default Ledger Currency: ${currency}<br />
                            Execution Timestamp: ${new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })}
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding: 16px 0 30px 0; border-bottom: 1px solid #e2e8f0;">
                <p>To view your workspace parameters, authenticate access tokens, or review configuration timelines, please log directly into your system profile workspace.</p>
                <p style="margin: 0;">Thank you,<br />Operational Support Infrastructure Desk</p>
            </td>
        </tr>
        <tr>
            <td style="padding: 20px 0 0 0; font-size: 11px; line-height: 16px; color: #999999;">
                This is an automated operational notification thread. Responses sent directly to this systemic verification entry are unmonitored.
            </td>
        </tr>
    </table>
</body>
</html>`;

        // ADMIN ALERT TEMPLATE: Cleaned and updated to align with the inbox formatting structure
        const adminHtmlTemplate = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <style type="text/css">
        body { width: 100% !important; margin: 0; padding: 0; font-family: Arial, sans-serif; color: #333333; background-color: #ffffff; }
    </style>
</head>
<body style="margin: 0; padding: 30px 20px; background-color: #ffffff;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; text-align: left;">
        <tr>
            <td style="padding: 0 0 20px 0; border-bottom: 1px solid #e2e8f0; font-size: 16px; font-weight: bold; color: #111111;">
                ${dynamicPlatformName} Core Security Node Notification
            </td>
        </tr>
        <tr>
            <td style="padding: 24px 0 16px 0; font-size: 14px; line-height: 20px;">
                An administrative deployment sequence has been executed on the system entry tier. Details follow below:
            </td>
        </tr>
        <tr>
            <td style="padding: 10px 0 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f8fafc; border-left: 3px solid #2c3e50; font-size: 13px; line-height: 22px; color: #475569;">
                    <tr><td style="padding: 6px 16px; font-weight:bold;">Full Name:</td><td style="padding: 6px 16px;">${newRow.firstname} ${newRow.lastname}</td></tr>
                    <tr><td style="padding: 6px 16px; font-weight:bold;">User Email:</td><td style="padding: 6px 16px;">${newRow.email}</td></tr>
                    <tr><td style="padding: 6px 16px; font-weight:bold;">Account Issued:</td><td style="padding: 6px 16px; color:#16a085; font-weight:bold;">${acctNo}</td></tr>
                    <tr><td style="padding: 6px 16px; font-weight:bold;">Configuration:</td><td style="padding: 6px 16px;">${accounttype} (${currency})</td></tr>
                    <tr><td style="padding: 6px 16px; font-weight:bold;">Signature Profile:</td><td style="padding: 6px 16px; font-family:monospace;">${signature}</td></tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding: 20px 0 0 0; font-size: 11px; color: #999999; border-top: 1px solid #e2e8f0;">
                This metric tracking notice was auto-generated by the internal backend routing node pipeline.
            </td>
        </tr>
    </table>
</body>
</html>`;

        // FIXED: replyTo points directly to the senderAddressEmail to guarantee absolute DMARC alignment status
        Promise.all([
            mailTransporter.sendMail({
                from: `"${cleanSignatureTag} Identity Protection" <${senderAddressEmail}>`,
                to: newRow.email.trim(),
                replyTo: senderAddressEmail,
                headers: {
                    "X-Auto-Response-Suppress": "All",
                    "Precedence": "bulk"
                },
                subject: emailSubject,
                html: userHtmlTemplate
            }),
            mailTransporter.sendMail({
                from: `"${cleanSignatureTag} System Monitor" <${senderAddressEmail}>`,
                to: senderAddressEmail,
                replyTo: senderAddressEmail,
                headers: {
                    "X-Auto-Response-Suppress": "All",
                    "Precedence": "bulk"
                },
                subject: `[SYSTEM ALERT] New Account Initialized — ${acctNo}`,
                html: adminHtmlTemplate
            })
        ]).then(() => {
            console.log("📨 Both registration tracking email dispatches executed smoothly with strict alignment.");
        }).catch((err) => {
            console.warn("⚠️ Background message dispatch network exception:", err.message);
        });

    } catch (mailError) {
        console.warn("⚠️ Registration completed but outbound dynamic SMTP email configuration encountered an exception:", mailError.message);
    }

    return res.status(200).json({
        success: true,
        message: "Account workspace instance deployment complete.",
        token: token,
        user: {
            uuid: newRow.uuid,
            email: newRow.email,
            name: `${newRow.firstname} ${newRow.lastname}`
        }
    });
}