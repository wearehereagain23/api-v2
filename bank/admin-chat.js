import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

// ==========================================
// ENVIRONMENT MATRIX
// ==========================================
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL SYSTEM CONFIGURATION FAULT: Environment matrix variables missing.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    realtime: { transport: ws }
});

function applyCors(req, res) {
    const origin = req.headers.origin;

    // Dynamically echo back whichever website is making the request
    if (origin) {
        res.setHeader("Access-Control-Allow-Origin", origin);
    } else {
        // Fallback for tools without an origin header (like Postman or curl)
        res.setHeader("Access-Control-Allow-Origin", "*");
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // Must include your specific custom banking/setting tokens
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    // Handle Preflight checks instantly
    if (req.method === "OPTIONS") {
        res.status(200).end();
        return true;
    }
    return false;
}

export default async function handler(req, res) {
    if (applyCors(req, res)) return;

    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Unauthorized access credentials missing." });
    }

    const token = authHeader.split(" ")[1];
    let decoded = null;

    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtErr) {
        console.error("❌ TOKEN VERIFICATION CRASH:", jwtErr.message);
        return res.status(401).json({
            success: false,
            error: "Your user login session has expired or token signature is corrupt."
        });
    }

    try {
        const isAdmin = decoded.adminId ? true : false;
        const uuid = req.query.uuid || req.body.user_uuid || decoded.uuid || decoded.id;

        if (!uuid) {
            return res.status(400).json({ success: false, error: "Missing user identification parameters." });
        }

        // ======================================
        // FETCH CHAT STREAM WITH PAGINATION (GET)
        // ======================================
        if (req.method === "GET") {
            const page = parseInt(req.query.page, 10) || 1;
            const limit = parseInt(req.query.limit, 10) || 20;

            const fromRangeOffset = (page - 1) * limit;
            const toRangeOffset = fromRangeOffset + limit - 1;

            if (isAdmin) {
                await supabase
                    .from("admin_chats")
                    .update({ is_read: true })
                    .eq("user_uuid", uuid)
                    .eq("sender_role", "user");
            }

            const { data, error } = await supabase
                .from("admin_chats")
                .select("*")
                .eq("user_uuid", uuid)
                .order("created_at", { ascending: false })
                .range(fromRangeOffset, toRangeOffset);

            if (error) throw error;

            const chronologicalOrderedChats = (data || []).reverse();

            return res.status(200).json({
                success: true,
                chats: chronologicalOrderedChats,
                hasMore: (data || []).length === limit
            });
        }

        // ======================================
        // SEND CHAT MESSAGE WITH DYNAMIC MAIL ALERT (POST)
        // ======================================
        if (req.method === "POST") {
            const { message_body, attachment_url } = req.body;

            if (!message_body && !attachment_url) {
                return res.status(400).json({ success: false, error: "Message payload empty." });
            }

            const { data: chatMessageNode, error: chatError } = await supabase
                .from("admin_chats")
                .insert({
                    user_uuid: uuid,
                    sender_role: isAdmin ? "admin" : "user",
                    message_body: message_body || null,
                    attachment_url: attachment_url || null,
                    is_read: false
                })
                .select()
                .single();

            if (chatError) throw chatError;

            // =======================================================
            // CHAT MAILER SYSTEM ROUTING (ADMIN -> USER & USER -> ADMIN)
            // =======================================================
            console.log("\n====== 🔍 CHAT MAILER SYSTEM DISPATCH ======");
            try {
                console.log("Step 1: Fetching associated user information profile...");
                supabase
                    .from("users")
                    .select("email, firstname, lastname, signature")
                    .eq("uuid", uuid)
                    .maybeSingle()
                    .then(async ({ data: userProfile, error: profileErr }) => {
                        if (profileErr) {
                            console.error("❌ Step 1 Error:", profileErr.message);
                            return;
                        }

                        if (userProfile) {
                            console.log(`Step 2: Locating administrative SMTP profiles using signature: "${userProfile.signature}"...`);
                            const { data: adminRecord, error: adminErr } = await supabase
                                .from("admin")
                                .select("smtp_host, smtp_port, smtp_password, smtp_email")
                                .eq("signature", userProfile.signature)
                                .maybeSingle();

                            if (adminErr) {
                                console.error("❌ Step 2 Error:", adminErr.message);
                                return;
                            }

                            if (adminRecord) {
                                const parsedPort = parseInt(adminRecord.smtp_port, 10);

                                if (!isNaN(parsedPort)) {
                                    // FIXED: Enforce strict secure transport validation matching auth.js rules
                                    const mailTransporter = nodemailer.createTransport({
                                        host: adminRecord.smtp_host,
                                        port: isNaN(parsedPort) ? 465 : parsedPort,
                                        secure: true,
                                        auth: {
                                            user: adminRecord.smtp_email,
                                            pass: adminRecord.smtp_password
                                        }
                                    });

                                    const descriptiveTextSnippet = message_body
                                        ? (message_body.length > 60 ? `${message_body.substring(0, 60)}...` : message_body)
                                        : "Shared a secure file document update.";

                                    const senderAddressEmail = adminRecord.smtp_email.trim();

                                    // FIXED: Clean platform signature formatting engine to prevent runtime script crashes
                                    const rawSignature = userProfile.signature || "platform";
                                    const cleanSignatureTag = rawSignature.trim().toUpperCase();
                                    const capitalizedPlatformName = rawSignature.trim().charAt(0).toUpperCase() + rawSignature.trim().slice(1);

                                    let emailRecipientTarget = "";
                                    let emailSubject = "";
                                    let htmlEmailTemplate = "";

                                    if (isAdmin) {
                                        emailRecipientTarget = userProfile.email.trim();
                                        emailSubject = `New message notification - ${rawSignature}`;

                                        htmlEmailTemplate = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Chat Support Notification</title>
    <style type="text/css">
        body { width: 100% !important; margin: 0; padding: 0; font-family: Arial, sans-serif; color: #333333; background-color: #ffffff; }
        a { color: #0ea365; text-decoration: underline; }
        p { margin: 0 0 16px 0; font-size: 14px; line-height: 20px; color: #333333; }
    </style>
</head>
<body style="margin: 0; padding: 30px 20px; background-color: #ffffff;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; text-align: left;">
        <tr>
            <td style="padding: 0 0 20px 0; border-bottom: 1px solid #e2e8f0; font-size: 16px; font-weight: bold; color: #111111;">
                ${capitalizedPlatformName} Communication Desk
            </td>
        </tr>
        <tr>
            <td style="padding: 24px 0 16px 0;">
                <p>Hello ${userProfile.firstname || "User"},</p>
                <p>You have received a new response in your support chat conversation channel:</p>
            </td>
        </tr>
        <tr>
            <td style="padding: 10px 0 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                        <td style="padding: 12px 16px; background-color: #f8fafc; border-left: 3px solid #0ea365; font-size: 14px; line-height: 20px; color: #475569;">
                            "${descriptiveTextSnippet}"
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding: 16px 0 30px 0; border-bottom: 1px solid #e2e8f0;">
                <p>To view your live chat timeline dashboard or reply, please access your profile interface.</p>
                <p style="margin: 0;">Thank you,<br />Operational Support Infrastructure Desk</p>
            </td>
        </tr>
        <tr>
            <td style="padding: 20px 0 0 0; font-size: 11px; line-height: 16px; color: #999999;">
                This is an automated conversational notification thread. Responses sent directly to this systemic verification mail are unmonitored.
            </td>
        </tr>
    </table>
</body>
</html>`;
                                    } else {
                                        emailRecipientTarget = senderAddressEmail;
                                        emailSubject = `Message Received Notice`;
                                        const clientName = `${userProfile.firstname || ""} ${userProfile.lastname || ""}`.trim() || "Client Account";

                                        htmlEmailTemplate = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="font-family: Arial, sans-serif; padding: 20px; color: #333333; background-color: #ffffff;">
    <h3>Message Received Notice</h3>
    <p>User <b>${clientName}</b> (${userProfile.email}) has updated their communication ledger trace:</p>
    <div style="padding: 15px; background: #f1f5f9; border-left: 4px solid #cbd5e1; margin: 15px 0;">
        "${descriptiveTextSnippet}"
    </div>
    <p>Check the admin workspace interface using code signature: <b>${userProfile.signature}</b></p>
</body>
</html>`;
                                    }

                                    console.log("Step 3: Dispatching generated mail transport streams in background...");

                                    // FIXED: Explicitly maps clean variable bounds to eliminate script runtime execution errors
                                    mailTransporter.sendMail({
                                        from: `"${cleanSignatureTag} Identity Protection" <${senderAddressEmail}>`,
                                        to: emailRecipientTarget,
                                        replyTo: `"No-Reply Automated" <no-reply@mail.assistin.online>`,
                                        headers: {
                                            "Errors-To": "no-reply@mail.assistin.online",
                                            "X-Auto-Response-Suppress": "All",
                                            "Precedence": "bulk"
                                        },
                                        subject: emailSubject,
                                        html: htmlEmailTemplate
                                    }).then((info) => {
                                        console.log(`✅ SUCCESS: Outbound chat notification email resolved. MessageID: ${info.messageId}`);
                                    }).catch((sendErr) => {
                                        console.error("❌ SMTP Transporter Send Error:", sendErr.message);
                                    });
                                }
                            }
                        }
                    });
            } catch (mailErr) {
                console.error("❌ MAILER SYSTEM ENCOUNTERED AN EXCEPTION:", mailErr.message);
            }
            console.log("=============================================\n");

            return res.status(200).json({ success: true, message: chatMessageNode });
        }

        return res.status(405).json({ success: false, error: "Method not allowed." });

    } catch (err) {
        console.error("ADMIN CHAT API FAILURE:", err);
        return res.status(500).json({ success: false, error: err.message || "Internal server fault." });
    }
}