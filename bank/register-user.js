import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";
import crypto from "crypto";

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

function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
}

// Fetch active SMTP Transporter from Admin Record
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

export default async function registerUserHandler(req, res) {
    // CORS Setup
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
        const payload = req.body;
        const {
            firstname, middlename, lastname, email, birth, gender,
            city, country, accounttype, currency, password, signature
        } = payload;

        if (!email || !password || !firstname || !lastname || !signature) {
            return res.status(400).json({ success: false, error: "Please fill out all required fields to complete your registration." });
        }

        const cleanEmail = email.trim().toLowerCase();
        const dynamicPlatformName = formatPlatformName(signature);

        // Check if user already exists
        const { data: existingUser } = await supabase
            .from("users")
            .select("uuid")
            .eq("email", cleanEmail)
            .eq("signature", signature)
            .maybeSingle();

        if (existingUser) {
            return res.status(400).json({ success: false, error: "An account with this email address already exists. Please sign in or use a different email." });
        }

        // Generate Account Number & explicit UUID
        const generatedAcctNumber = Math.floor(1000000000 + Math.random() * 9000000000).toString();
        const generatedUuid = crypto.randomUUID();

        const newUserPayload = {
            uuid: generatedUuid,
            firstname: firstname.trim(),
            middlename: (middlename || "").trim(),
            lastname: lastname.trim(),
            email: cleanEmail,
            dateOfBirth: birth,
            gender,
            city: (city || "").trim(),
            country,
            accttype: accounttype,
            currency,
            password,
            accountNumber: generatedAcctNumber,
            signature,
            pin: null,
            restricted: false,
            activeuser: true,
            attempt: 0,
            attempt2: 0
        };

        const { data: createdUser, error: insertError } = await supabase
            .from("users")
            .insert([newUserPayload])
            .select()
            .single();

        if (insertError) {
            console.error("❌ Registration Database Error:", insertError.message);
            return res.status(500).json({ success: false, error: "We encountered an issue creating your account. Please try again shortly." });
        }


        // Handle Email Operations (User Welcome & Admin Alert)
        try {
            const { transporter, adminEmail } = await getAdminTransporter(signature);

            // Extract domain from admin email to form a clean no-reply address
            const domain = adminEmail.includes("@") ? adminEmail.split("@")[1] : "yourdomain.com";
            const noReplyEmail = `no-reply@${domain}`;

            // 1. User Welcome Email (No-Reply)
            const welcomeHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to ${dynamicPlatformName}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f6f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; color: #334155;">
    <div style="display: none; max-height: 0px; overflow: hidden;">
        Your new ${dynamicPlatformName} account is ready. Account Number: ${generatedAcctNumber}
    </div>
    
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f6f9; padding: 40px 10px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 580px; background-color: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden;">
                    <tr>
                        <td style="padding: 30px 40px; background-color: #0f172a; text-align: left;">
                            <h1 style="margin: 0; font-size: 20px; font-weight: 600; color: #ffffff; letter-spacing: -0.2px;">${dynamicPlatformName}</h1>
                        </td>
                    </tr>
                    
                    <tr>
                        <td style="padding: 35px 40px;">
                            <p style="margin: 0 0 16px 0; font-size: 16px; line-height: 1.5; color: #1e293b;">Hello ${firstname.trim()},</p>
                            <p style="margin: 0 0 24px 0; font-size: 15px; line-height: 1.6; color: #475569;">Thank you for registering with ${dynamicPlatformName}. Your account has been set up successfully. Below are your account profile details:</p>
                            
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 24px;">
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #64748b; font-weight: 600;">Account Number</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 14px; color: #0f172a; font-weight: 600; text-align: right;">${generatedAcctNumber}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #64748b; font-weight: 600;">Account Type</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 14px; color: #0f172a; text-align: right;">${accounttype}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; font-size: 13px; color: #64748b; font-weight: 600;">Currency</td>
                                    <td style="padding: 12px 16px; font-size: 14px; color: #0f172a; text-align: right;">${currency}</td>
                                </tr>
                            </table>

                            <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 1.5; color: #64748b;">You can log in to your dashboard at any time to manage your funds and view transaction records.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <td style="padding: 24px 40px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; line-height: 1.5; text-align: center;">
                            This is an unmonitored automated email. Please do not reply directly to this message.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;

            const welcomeText = `Hello ${firstname.trim()},\n\nWelcome to ${dynamicPlatformName}! Your account has been created successfully.\n\nAccount Details:\n- Account Number: ${generatedAcctNumber}\n- Account Type: ${accounttype}\n- Currency: ${currency}\n\nPlease note: This is an unmonitored address. Do not reply to this email.`;

            transporter.sendMail({
                from: `"${dynamicPlatformName} Notifications" <${adminEmail}>`,
                replyTo: noReplyEmail, // Redirects replies to unmonitored no-reply inbox
                to: cleanEmail,
                subject: `Welcome to ${dynamicPlatformName} - Account Confirmation`,
                text: welcomeText,
                html: welcomeHtml
            }).catch(err => console.warn("User welcome email warning:", err.message));

            // 2. Admin Alert Email
            const adminAlertHtml = `<!DOCTYPE html>
            <html>
            <body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial, sans-serif; color:#333;">
                <div style="max-width:550px; margin:20px auto; background:#fff; border-radius:8px; padding:25px;">
                    <h3 style="color:#2c3e50; margin-top:0;">New Registration Alert (${dynamicPlatformName})</h3>
                    <p>A new user account was just registered:</p>
                    <table style="width:100%; border-collapse:collapse; font-size:13px;">
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb;"><strong>Full Name:</strong></td><td style="padding:8px; border:1px solid #ddd;">${firstname} ${lastname}</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb;"><strong>Email Address:</strong></td><td style="padding:8px; border:1px solid #ddd;">${cleanEmail}</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb;"><strong>Account Number:</strong></td><td style="padding:8px; border:1px solid #ddd;">${generatedAcctNumber}</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb;"><strong>Account Type:</strong></td><td style="padding:8px; border:1px solid #ddd;">${accounttype} (${currency})</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd; background:#f9fafb;"><strong>UUID:</strong></td><td style="padding:8px; border:1px solid #ddd;">${createdUser.uuid}</td></tr>
                    </table>
                </div>
            </body>
            </html>`;

            transporter.sendMail({
                from: `"${dynamicPlatformName} System" <${adminEmail}>`,
                to: adminEmail,
                subject: `New User Registration: ${cleanEmail}`,
                html: adminAlertHtml
            }).catch(err => console.warn("Admin registration alert warning:", err.message));

        } catch (mailError) {
            console.warn("SMTP initialization warning on registration:", mailError.message);
        }



        // Generate JWT Token
        const token = jwt.sign(
            { uuid: createdUser.uuid, email: createdUser.email, signature },
            JWT_SECRET,
            { expiresIn: "24h" }
        );

        return res.status(200).json({
            success: true,
            message: "Your account has been created successfully.",
            token,
            user: {
                uuid: createdUser.uuid,
                email: createdUser.email,
                firstname: createdUser.firstname,
                lastname: createdUser.lastname,
                accountNumber: createdUser.accountNumber,
                accttype: createdUser.accttype,
                currency: createdUser.currency
            }
        });

    } catch (globalError) {
        console.error("❌ Critical Registration Fault:", globalError);
        return res.status(500).json({ success: false, error: "An unexpected server error occurred. Please try again later." });
    }
}