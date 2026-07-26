import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: Required environment variables are missing.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

const otpStore = new Map();

function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
}

async function getAdminTransporter(signature) {
    const { data: adminRecord, error } = await supabase
        .from("admin")
        .select("smtp_host, smtp_port, smtp_password, smtp_email")
        .eq("signature", signature)
        .maybeSingle();

    if (error || !adminRecord) {
        throw new Error(error ? error.message : `No administrative environment found for signature '${signature}'.`);
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

// Helper function to resolve IP address to Location using ip-api.com
async function getLocationFromIp(ip) {
    if (!ip || ip === "Unknown IP" || ip === "127.0.0.1" || ip === "::1") {
        return "Localhost / Internal Network";
    }

    try {
        const cleanIp = ip.split(",")[0].trim();
        const response = await fetch(`http://ip-api.com/json/${cleanIp}`);

        if (!response.ok) return "Unknown Location";

        const data = await response.json();
        if (data.status === "success") {
            return `${data.city || ""}, ${data.regionName || ""}, ${data.country || ""}`.replace(/^, |, $/g, '');
        }
    } catch (err) {
        console.warn("⚠️ Location Lookup Warning:", err.message);
    }

    return "Unknown Location";
}

// Helper: Send admin login alert email with device, browser, and country location metadata
async function sendAdminLoginNotification(req, user, signature, is2FA) {
    const dynamicPlatformName = formatPlatformName(signature);
    const { transporter, adminEmail } = await getAdminTransporter(signature);

    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "Unknown IP";
    const userAgent = req.headers['user-agent'] || "Unknown Device/Browser";

    const userLocation = await getLocationFromIp(rawIp);
    const is2FAStatus = is2FA ? "True" : "False";

    const emailSubject = `Login Alert: ${user.firstname} ${user.lastname} Signed In`;
    const emailBody = `
        <h3>User Sign-in Notification</h3>
        <p><strong>Platform:</strong> ${dynamicPlatformName}</p>
        <p><strong>Name:</strong> ${user.firstname} ${user.lastname}</p>
        <p><strong>Email:</strong> ${user.email}</p>
        <p><strong>Account Number:</strong> ${user.accountNumber || "N/A"}</p>
        <p><strong>2FA Enabled:</strong> ${is2FAStatus}</p>
        <p><strong>IP Address:</strong> ${rawIp}</p>
        <p><strong>Location:</strong> ${userLocation}</p>
        <p><strong>Device / Browser Info:</strong> ${userAgent}</p>
        <p><strong>Time:</strong> ${new Date().toISOString()}</p>
    `;

    await transporter.sendMail({
        from: `"${dynamicPlatformName} Security" <${adminEmail}>`,
        to: adminEmail,
        subject: emailSubject,
        html: emailBody
    });
}

async function sendOTPEmail(userEmail, firstname, otpCode, signature, subjectText, introText) {
    const dynamicPlatformName = formatPlatformName(signature);
    const { transporter, adminEmail } = await getAdminTransporter(signature);

    const domain = adminEmail.includes("@") ? adminEmail.split("@")[1] : "yourdomain.com";
    const noReplyEmail = `no-reply@${domain}`;

    const otpHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${subjectText}</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f6f9; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color:#334155;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f4f6f9; padding:40px 10px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:580px; background-color:#ffffff; border-radius:8px; border:1px solid #e2e8f0; overflow:hidden;">
                    <tr>
                        <td style="padding:30px 40px; background-color:#0f172a; text-align:left;">
                            <h1 style="margin:0; font-size:20px; font-weight:600; color:#ffffff;">${dynamicPlatformName}</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:35px 40px;">
                            <p style="margin:0 0 16px 0; font-size:16px; color:#1e293b;">Hello ${firstname || "Valued Customer"},</p>
                            <p style="margin:0 0 24px 0; font-size:15px; line-height:1.6; color:#475569;">${introText}</p>
                            
                            <div style="background-color:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:20px; text-align:center; margin-bottom:24px;">
                                <span style="font-size:32px; font-weight:700; letter-spacing:6px; color:#0f172a;">${otpCode}</span>
                            </div>

                            <p style="margin:0 0 16px 0; font-size:13px; color:#64748b;">This code will expire in 10 minutes.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;

    await transporter.sendMail({
        from: `"${dynamicPlatformName} Security" <${adminEmail}>`,
        replyTo: noReplyEmail,
        to: userEmail,
        subject: `${subjectText} - ${dynamicPlatformName}`,
        text: `Hello ${firstname || "Valued Customer"},\n\n${introText}\n\nCode: ${otpCode}\n\nExpires in 10 minutes.`,
        html: otpHtml
    });
}

export default async function loginUserHandler(req, res) {
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "Invalid request method." });
    }

    try {
        const { action = "login", email, password, signature, user_id, otp, credential_id } = req.body;

        // 1. STANDARD PASSWORD LOGIN
        if (action === "login") {
            if (!email || !password || !signature) {
                return res.status(400).json({ success: false, error: "Please provide email, password, and signature." });
            }

            const cleanEmail = email.trim().toLowerCase();

            const { data: user, error: fetchErr } = await supabase
                .from("users")
                .select(`
                    id, uuid, firstname, lastname, email, password, restricted, activeuser, "2fa", "accountNumber", accttype, currency, biometric_credential_id
                `)
                .eq("email", cleanEmail)
                .eq("signature", signature)
                .maybeSingle();

            if (fetchErr || !user || user.password !== password) {
                return res.status(401).json({ success: false, error: "Invalid email address or password." });
            }

            if (user.restricted || user.activeuser === false) {
                return res.status(403).json({ success: false, error: "Your account is currently restricted. Please contact support." });
            }

            const is2FAEnabled = user["2fa"] === true || user["2fa"] === "true";

            if (is2FAEnabled) {
                const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
                otpStore.set(user.uuid, {
                    otp: generatedOtp,
                    expiresAt: Date.now() + 10 * 60 * 1000
                });

                try {
                    await sendOTPEmail(
                        user.email,
                        user.firstname,
                        generatedOtp,
                        signature,
                        "Login Security Verification Code",
                        "A sign-in request was detected for your account. Please enter the verification code below to authorize access:"
                    );
                } catch (mailErr) {
                    console.warn("⚠️ OTP Email Dispatch Warning:", mailErr.message);
                }

                return res.status(200).json({
                    success: true,
                    requires_2fa: true,
                    message: "Credentials verified. Security code dispatched.",
                    user_id: user.uuid
                });
            } else {
                try {
                    await sendAdminLoginNotification(req, user, signature, false);
                } catch (adminMailErr) {
                    console.warn("⚠️ Admin Notification Email Warning:", adminMailErr.message);
                }

                const token = jwt.sign(
                    { uuid: user.uuid, email: user.email, signature },
                    JWT_SECRET,
                    { expiresIn: "24h" }
                );

                return res.status(200).json({
                    success: true,
                    requires_2fa: false,
                    message: "Authentication successful.",
                    token: token,
                    user: {
                        uuid: user.uuid,
                        email: user.email,
                        firstname: user.firstname,
                        lastname: user.lastname,
                        accountNumber: user["accountNumber"],
                        accttype: user.accttype,
                        currency: user.currency,
                        biometric_credential_id: user.biometric_credential_id
                    }
                });
            }
        }

        // 2. REGISTER BIOMETRIC CREDENTIAL
        if (action === "register_biometrics") {
            if (!user_id || !credential_id || !signature) {
                return res.status(400).json({ success: false, error: "Missing biometric registration details." });
            }

            const { error: updateErr } = await supabase
                .from("users")
                .update({ biometric_credential_id: credential_id })
                .eq("uuid", user_id);

            if (updateErr) {
                return res.status(500).json({ success: false, error: "Failed to store biometric registration." });
            }

            return res.status(200).json({ success: true, message: "Biometrics successfully registered." });
        }

        // 3. GET BIOMETRIC AUTH CHALLENGE
        if (action === "get_biometric_challenge") {
            if (!email || !signature) {
                return res.status(400).json({ success: false, error: "Email and signature are required." });
            }

            const cleanEmail = email.trim().toLowerCase();

            const { data: user } = await supabase
                .from("users")
                .select("biometric_credential_id")
                .eq("email", cleanEmail)
                .eq("signature", signature)
                .maybeSingle();

            if (!user || !user.biometric_credential_id) {
                return res.status(400).json({ success: false, error: "No biometric credentials registered for this user." });
            }

            return res.status(200).json({
                success: true,
                challenge: Buffer.from("onflex_sec_challenge").toString("base64"),
                credentialId: user.biometric_credential_id
            });
        }

        // 4. LOGIN WITH BIOMETRICS
        if (action === "login_biometric") {
            if (!email || !signature) {
                return res.status(400).json({ success: false, error: "Missing biometric authentication parameters." });
            }

            const cleanEmail = email.trim().toLowerCase();

            const { data: user, error: fetchErr } = await supabase
                .from("users")
                .select(`
                    id, uuid, firstname, lastname, email, restricted, activeuser, "2fa", "accountNumber", accttype, currency, biometric_credential_id
                `)
                .eq("email", cleanEmail)
                .eq("signature", signature)
                .maybeSingle();

            if (fetchErr || !user) {
                return res.status(401).json({ success: false, error: "Biometric authentication failed. User account not found." });
            }

            if (user.restricted || user.activeuser === false) {
                return res.status(403).json({ success: false, error: "Your account is currently restricted. Please contact support." });
            }

            const is2FAEnabled = user["2fa"] === true || user["2fa"] === "true";

            if (is2FAEnabled) {
                const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
                otpStore.set(user.uuid, {
                    otp: generatedOtp,
                    expiresAt: Date.now() + 10 * 60 * 1000
                });

                try {
                    await sendOTPEmail(
                        user.email,
                        user.firstname,
                        generatedOtp,
                        signature,
                        "Login Security Verification Code",
                        "A biometric sign-in request was detected. Enter the code below to authorize access:"
                    );
                } catch (mailErr) {
                    console.warn("⚠️ Biometric OTP Email Dispatch Warning:", mailErr.message);
                }

                return res.status(200).json({
                    success: true,
                    requires_2fa: true,
                    message: "Biometrics verified. Security code dispatched.",
                    user_id: user.uuid
                });
            } else {
                try {
                    await sendAdminLoginNotification(req, user, signature, false);
                } catch (adminMailErr) {
                    console.warn("⚠️ Admin Notification Email Warning:", adminMailErr.message);
                }

                const token = jwt.sign(
                    { uuid: user.uuid, email: user.email, signature },
                    JWT_SECRET,
                    { expiresIn: "24h" }
                );

                return res.status(200).json({
                    success: true,
                    requires_2fa: false,
                    message: "Biometric authentication successful.",
                    token: token,
                    user: {
                        uuid: user.uuid,
                        email: user.email,
                        firstname: user.firstname,
                        lastname: user.lastname,
                        accountNumber: user["accountNumber"],
                        accttype: user.accttype,
                        currency: user.currency,
                        biometric_credential_id: user.biometric_credential_id
                    }
                });
            }
        }

        // 5. VERIFY LOGIN 2FA OTP
        if (action === "verify_otp") {
            if (!user_id || !otp || !signature) {
                return res.status(400).json({ success: false, error: "Missing verification parameters." });
            }

            const storedData = otpStore.get(user_id);
            if (!storedData || Date.now() > storedData.expiresAt) {
                if (storedData) otpStore.delete(user_id);
                return res.status(400).json({ success: false, error: "Verification code has expired or is invalid." });
            }

            if (storedData.otp !== otp.trim()) {
                return res.status(401).json({ success: false, error: "Incorrect verification code." });
            }

            otpStore.delete(user_id);

            const { data: user, error: userErr } = await supabase
                .from("users")
                .select("uuid, email, firstname, lastname, accountNumber, accttype, currency")
                .eq("uuid", user_id)
                .single();

            if (userErr || !user) {
                return res.status(404).json({ success: false, error: "User profile not found." });
            }

            try {
                await sendAdminLoginNotification(req, user, signature, true);
            } catch (adminMailErr) {
                console.warn("⚠️ Admin Notification Email Warning:", adminMailErr.message);
            }

            const token = jwt.sign(
                { uuid: user.uuid, email: user.email, signature },
                JWT_SECRET,
                { expiresIn: "24h" }
            );

            return res.status(200).json({
                success: true,
                message: "Authentication successful.",
                token,
                user: {
                    uuid: user.uuid,
                    email: user.email,
                    firstname: user.firstname,
                    lastname: user.lastname,
                    accountNumber: user.accountNumber,
                    accttype: user.accttype,
                    currency: user.currency
                }
            });
        }

        // 6. FORGOT PASSWORD REQUEST
        if (action === "forgot_password_request") {
            if (!email || !signature) {
                return res.status(400).json({ success: false, error: "Please enter a valid email address." });
            }

            const cleanEmail = email.trim().toLowerCase();

            const { data: user } = await supabase
                .from("users")
                .select("uuid, firstname, email, restricted")
                .eq("email", cleanEmail)
                .eq("signature", signature)
                .maybeSingle();

            if (!user) {
                return res.status(404).json({ success: false, error: "No account found associated with this email address." });
            }

            if (user.restricted) {
                return res.status(403).json({ success: false, error: "Account access restricted due to security locking conditions." });
            }

            const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
            otpStore.set(user.uuid, {
                otp: generatedOtp,
                expiresAt: Date.now() + 10 * 60 * 1000
            });

            try {
                await sendOTPEmail(
                    user.email,
                    user.firstname,
                    generatedOtp,
                    signature,
                    "Password Reset Request Code",
                    "We received a request to reset your account password. Use the code below to proceed:"
                );
            } catch (mailErr) {
                console.warn("⚠️ Password Recovery Email Warning:", mailErr.message);
            }

            return res.status(200).json({
                success: true,
                message: "Password recovery token dispatched.",
                user_id: user.uuid
            });
        }

        // 7. VERIFY FORGOT PASSWORD OTP
        if (action === "verify_password_otp") {
            if (!user_id || !otp) {
                return res.status(400).json({ success: false, error: "Missing verification parameters." });
            }

            const storedData = otpStore.get(user_id);

            if (!storedData || Date.now() > storedData.expiresAt) {
                if (storedData) otpStore.delete(user_id);
                return res.status(400).json({ success: false, error: "Verification code has expired." });
            }

            if (storedData.otp !== otp.trim()) {
                return res.status(401).json({ success: false, error: "Invalid verification code." });
            }

            return res.status(200).json({
                success: true,
                message: "Recovery token verified successfully."
            });
        }

        // 8. COMMIT NEW PASSWORD
        if (action === "commit_new_password") {
            if (!user_id || !password) {
                return res.status(400).json({ success: false, error: "Please provide a valid new password." });
            }

            if (password.length < 8) {
                return res.status(400).json({ success: false, error: "Password must be at least 8 characters long." });
            }

            const { error: updateErr } = await supabase
                .from("users")
                .update({
                    password: String(password).trim(),
                    attempt: 0,
                    attempt2: 0,
                    restricted: false,
                    activeuser: true
                })
                .eq("uuid", user_id);

            if (updateErr) {
                return res.status(500).json({ success: false, error: "Could not update password. Please try again." });
            }

            otpStore.delete(user_id);

            return res.status(200).json({
                success: true,
                message: "Your password has been updated successfully."
            });
        }

        return res.status(400).json({ success: false, error: "Unsupported authentication action request." });

    } catch (globalError) {
        console.error("❌ Critical Login Handler Fault:", globalError);
        return res.status(500).json({ success: false, error: "An unexpected server error occurred." });
    }
}