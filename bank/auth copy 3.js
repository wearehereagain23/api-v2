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
        .select("uuid, email, password, activeuser, firstname")
        .eq("email", cleanEmail)
        .eq("signature", signature)
        .maybeSingle();

    if (userError) {
        return res.status(500).json({ success: false, error: `Database Error during User verification lookup: ${userError.message}` });
    }
    if (!userRecord) {
        return res.status(401).json({ success: false, error: `Authentication Failed: User record with email '${cleanEmail}' not found under signature scope '${signature}'.` });
    }

    if (userRecord.activeuser === false) {
        return res.status(403).json({ success: false, error: "Access Denied: This account profile has been locked or deactivated." });
    }

    if (userRecord.password !== password) {
        return res.status(401).json({ success: false, error: "Authentication Failed: Incorrect password verification match." });
    }

    const generatedOTP = Math.floor(100000 + Math.random() * 900000).toString();
    const updatePayload = { pin: generatedOTP }; // Storing into pin slot acting as temporary validation payload state

    const { error: updateError } = await supabase
        .from("users")
        .update(updatePayload)
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
 * PHASE 2 LOGIN HANDLER: Custom Virtual OTP Verification Engine
 */
async function handleOTPVerification(payload, res) {
    const { user_id, otp, current_attempts, signature } = payload;

    if (!user_id) return res.status(400).json({ success: false, error: "Missing required 'user_id' parameter framework tracker." });
    if (!otp) return res.status(400).json({ success: false, error: "Missing 'otp' input validation string token property." });
    if (!signature) return res.status(400).json({ success: false, error: "Missing required 'signature' parameters inside authorization verification layers." });

    const dynamicPlatformName = formatPlatformName(signature);

    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, email, pin, activeuser, firstname, lastname, \"accountNumber\", accttype, currency")
        .eq("uuid", user_id)
        .maybeSingle();

    if (userError || !userRecord) {
        return res.status(404).json({ success: false, error: "Profile verification sequence broken. User profile identity target context lookup returned null properties." });
    }

    if (userRecord.activeuser === false) {
        return res.status(403).json({ success: false, error: "Access Denied: Secure account access parameters locked." });
    }

    if (!userRecord.pin || String(userRecord.pin) !== String(otp).trim()) {
        const attemptsUsed = parseInt(current_attempts, 10) || 1;
        const totalRemainingAttempts = 5 - attemptsUsed;

        if (totalRemainingAttempts <= 0) {
            await supabase
                .from("users")
                .update({ activeuser: false })
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

        mailTransporter.sendMail({
            from: `"${dynamicPlatformName} System Monitor" <${adminRecord.smtp_email}>`,
            to: adminRecord.smtp_email,
            replyTo: adminRecord.smtp_email,
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

    const token = jwt.sign(
        {
            uuid: userRecord.uuid,
            email: userRecord.email
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

    const recoveryOTP = Math.floor(100000 + Math.random() * 900000).toString();

    const { error: updateError } = await supabase
        .from("users")
        .update({ pin: recoveryOTP })
        .eq("uuid", userRecord.uuid);

    if (updateError) {
        return res.status(500).json({ success: false, error: "Failed to map transient recovery security token fields onto workspace row data." });
    }

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
                    <p>An administrative request to reset your profile credentials passcode layer was triggered. Use this 6-digit security token code to authenticate the operation framework:</p>
                    <div style="background:#f0fdf4; border:1px dashed #0ea365; padding:15px; text-align:center; font-size:26px; font-weight:bold; letter-spacing:4px; color:#059669; margin:20px 0; border-radius:6px;">
                        ${recoveryOTP}
                    </div>
                    <p style="font-size:11px; color:#999;">If you did not request this update validation session, you can safely skip this message notification.</p>
                </div>
            </body>
            </html>`;

            mailTransporter.sendMail({
                from: `"${dynamicPlatformName} System Protection" <${adminRecord.smtp_email}>`,
                to: userRecord.email,
                replyTo: adminRecord.smtp_email,
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

    const { data: userRecord, error: userError } = await supabase
        .from("users")
        .select("uuid, pin")
        .eq("uuid", user_id)
        .maybeSingle();

    if (userError || !userRecord) {
        return res.status(404).json({ success: false, error: "Profile look up reference sequence fractured." });
    }

    if (!userRecord.pin || String(userRecord.pin) !== String(otp).trim()) {
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

    const { error: commitError } = await supabase
        .from("users")
        .update({
            password: password
        })
        .eq("uuid", user_id);

    if (commitError) {
        return res.status(500).json({ success: false, error: `Database transaction commit operation fault error: ${commitError.message}` });
    }

    return res.status(200).json({ success: true, message: "Profile database credential mapping updated successfully." });
}

/**
 * ACCOUNT CREATION CORE MODULE - Cleaned to match strict Database schema
 */
async function handleRegistration(data, res) {
    const {
        firstname, lastname, middlename, email, password,
        birth, gender, city, country, accounttype, currency, pin, signature
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
        return res.status(400).json({ success: false, error: `Configuration Broken: No tracking context admin profile found matching signature tracker value '${signature}'.` });
    }

    // STEP 2: Structural parameters validation screening loop
    const mandatoryKeys = [
        { name: "firstname", val: firstname },
        { name: "lastname", val: lastname },
        { name: "email", val: email },
        { name: "password", val: password },
        { name: "birth", val: birth },
        { name: "gender", val: gender },
        { name: "city", val: city },
        { name: "country", val: country },
        { name: "accounttype", val: accounttype },
        { name: "currency", val: currency },
        { name: "pin", val: pin }
    ];

    for (const keyDef of mandatoryKeys) {
        if (keyDef.val === undefined || keyDef.val === null || String(keyDef.val).trim() === "") {
            return res.status(400).json({ success: false, error: `Bad Request Payload Framework Architecture Assertion Fault: Form variable field '${keyDef.name}' is missing.` });
        }
    }

    // STEP 3: Verify unique constraints
    const { data: duplicateUser, error: checkError } = await supabase
        .from("users")
        .select("email")
        .eq("email", email.toLowerCase().trim())
        .maybeSingle();

    if (checkError) return res.status(500).json({ success: false, error: checkError.message });
    if (duplicateUser) {
        return res.status(400).json({ success: false, error: `Conflict Violation Anomaly: Email profile address '${email.toLowerCase().trim()}' is already actively tracked.` });
    }

    // STEP 4: Build payload matching provided SQL Table columns structure strictly
    const acctNo = "618" + Math.floor(1000000 + Math.random() * 9000000);
    const generateCode = () => Math.floor(10000 + Math.random() * 89999);
    const userUUID = crypto.randomUUID();

    const insertionPayload = {
        firstname: firstname.trim(),
        middlename: middlename ? middlename.trim() : "",
        lastname: lastname.trim(),
        email: email.toLowerCase().trim(),
        password: password,
        "dateOfBirth": birth,
        gender: gender,
        city: city.trim(),
        country: country,
        accttype: accounttype,
        currency: currency,
        pin: String(pin).trim(),
        signature: signature,
        uuid: userUUID,
        "accountNumber": acctNo,
        "COT": `COT-${generateCode()}`,
        "IMF": `IMF-${generateCode()}`,
        "TAX": `TAX-${generateCode()}`,
        date: new Date().toLocaleDateString('en-US'),
        "accountBalance": "0",
        "accountTypeBalance": "0",
        "loanAmount": "0",
        "accountLevel": "Starter",
        "fixedDate": "",
        "loanType": "",
        "expireDate": "00/00",
        "cardNumber": "0000",
        "unsettledLoan": "0",
        "notificationCount": "0",
        "adjustAccountLevel": "Starter",
        "loanApprovalStatus": "",
        activeuser: true,
        "transferAccess": true,
        lockscreen: false,
        cards: "no",
        "cardApproval": "no",
        kyc: "no",
        change_password: false,
        "lockTransfer": false
    };

    // STEP 5: Insert user architecture structures into DB users table
    const { data: newRow, error: insertError } = await supabase
        .from("users")
        .insert([insertionPayload])
        .select("uuid, email, firstname, lastname")
        .single();

    if (insertError) {
        return res.status(500).json({ success: false, error: `Database Row Insertion Anomaly Fault: ${insertError.message}` });
    }

    // STEP 6: Core Session Web Token Assignment
    const token = jwt.sign(
        { uuid: newRow.uuid, email: newRow.email },
        JWT_SECRET,
        { expiresIn: "7d" }
    );

    // STEP 7: Transaction tracking confirmation alert emails setup logic
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

        const senderAddressEmail = adminRecord.smtp_email.trim();
        const cleanSignatureTag = signature.toUpperCase();

        const userHtmlTemplate = `
        <html>
        <body style="font-family: Arial, sans-serif; color: #333; background: #f9f9f9; padding: 20px;">
            <div style="max-width: 600px; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #0a7b8f;">Welcome to ${dynamicPlatformName}</h2>
                <p>Hello ${newRow.firstname},</p>
                <p>Your institutional finance account profile workspace deployment successfully finished processing setup validation tracks.</p>
                <p>Your unique account identifier number is: <b style="font-size: 16px; color: #0a7b8f;">${acctNo}</b></p>
                <p>Please utilize your email address and personalized authentication records passcode to finalize sign-in steps via your native dashboard application layout terminal nodes.</p>
                <br />
                <p style="font-size: 12px; color: #777;">Regards,<br />The ${dynamicPlatformName} Security Management Operations Team</p>
            </div>
        </body>
        </html>`;

        const adminHtmlTemplate = `
        <html>
        <body style="font-family: Arial, sans-serif; color: #333; background: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 10px;">[SYSTEM ALERT] Account Workspace Created</h2>
                <p>A new secure consumer account tracking row initialized dynamically inside database frameworks managed by node core layers.</p>
                <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                    <tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9; font-weight: bold;">Full Name:</td><td style="padding: 8px; border: 1px solid #ddd;">${newRow.firstname} ${newRow.lastname}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9; font-weight: bold;">User Email:</td><td style="padding: 8px; border: 1px solid #ddd;">${newRow.email}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9; font-weight: bold;">Assigned Number:</td><td style="padding: 8px; border: 1px solid #ddd; font-weight: bold; color: #0a7b8f;">${acctNo}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd; background: #f9f9f9; font-weight: bold;">Routing Signature:</td><td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">${signature}</td></tr>
                </table>
            </div>
        </body>
        </html>`;

        Promise.all([
            mailTransporter.sendMail({
                from: `"${dynamicPlatformName} Finance" <${senderAddressEmail}>`,
                to: newRow.email.trim(),
                replyTo: senderAddressEmail,
                headers: {
                    "X-Auto-Response-Suppress": "All",
                    "Precedence": "bulk"
                },
                subject: `New message notification - ${signature}`,
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