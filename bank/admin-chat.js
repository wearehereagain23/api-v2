import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

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
    if (origin) {
        res.setHeader("Access-Control-Allow-Origin", origin);
    } else {
        res.setHeader("Access-Control-Allow-Origin", "*");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target, x-signature, X-Signature");
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
        res.status(200).end();
        return true;
    }
    return false;
}

function formatPlatformName(signature) {
    if (!signature || typeof signature !== "string") return "Platform";
    const cleanStr = signature.trim();
    return cleanStr.charAt(0).toUpperCase() + cleanStr.slice(1);
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
        const isAdmin = Boolean(decoded.adminId || decoded.role === "admin" || decoded.isAdmin);
        const targetUserUuid = req.body?.user_uuid || req.query?.uuid || (isAdmin ? null : (decoded.uuid || decoded.id));

        // ======================================
        // FETCH CHAT STREAM WITH PAGINATION (GET)
        // ======================================
        if (req.method === "GET") {
            const fetchUuid = req.query.uuid || targetUserUuid;
            if (!fetchUuid) {
                return res.status(400).json({ success: false, error: "Missing user identification parameters." });
            }

            const page = parseInt(req.query.page, 10) || 1;
            const limit = parseInt(req.query.limit, 10) || 20;

            const fromRangeOffset = (page - 1) * limit;
            const toRangeOffset = fromRangeOffset + limit - 1;

            if (isAdmin) {
                await supabase
                    .from("admin_chats")
                    .update({ is_read: true })
                    .eq("user_uuid", fetchUuid)
                    .eq("sender_role", "user");
            }

            const { data, error } = await supabase
                .from("admin_chats")
                .select("*")
                .eq("user_uuid", fetchUuid)
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
        // SEND CHAT MESSAGE WITH SMTP EMAIL ALERT (POST)
        // ======================================
        if (req.method === "POST") {
            const { message_body, attachment_url, user_uuid } = req.body;
            const activeClientTargetUuid = user_uuid || targetUserUuid;

            if (!activeClientTargetUuid) {
                return res.status(400).json({ success: false, error: "Missing user identification parameters." });
            }

            if (!message_body && !attachment_url) {
                return res.status(400).json({ success: false, error: "Message payload empty." });
            }

            const { data: chatMessageNode, error: chatError } = await supabase
                .from("admin_chats")
                .insert({
                    user_uuid: activeClientTargetUuid,
                    sender_role: isAdmin ? "admin" : "user",
                    message_body: message_body || null,
                    attachment_url: attachment_url || null,
                    is_read: false
                })
                .select()
                .single();

            if (chatError) throw chatError;

            // Direct Async Background SMTP Engine
            (async () => {
                try {
                    let userProfile = null;

                    // Fetch client profile
                    const { data: profileByUuid } = await supabase
                        .from("users")
                        .select("email, firstname, lastname, signature")
                        .eq("uuid", activeClientTargetUuid)
                        .maybeSingle();

                    userProfile = profileByUuid;

                    if (!userProfile && !isNaN(parseInt(activeClientTargetUuid, 10))) {
                        const { data: profileById } = await supabase
                            .from("users")
                            .select("email, firstname, lastname, signature")
                            .eq("id", parseInt(activeClientTargetUuid, 10))
                            .maybeSingle();

                        userProfile = profileById;
                    }

                    const reqSignature = req.headers["x-signature"] || req.headers["X-Signature"] || decoded.signature;
                    const userSignature = userProfile?.signature || reqSignature;

                    let adminRecord = null;

                    // Match admin record using signature logic (identical to auth.js)
                    if (userSignature) {
                        const { data: sigAdmin } = await supabase
                            .from("admin")
                            .select("smtp_host, smtp_port, smtp_password, smtp_email")
                            .eq("signature", userSignature)
                            .maybeSingle();
                        adminRecord = sigAdmin;
                    }

                    if (!adminRecord) {
                        const { data: defaultAdmin } = await supabase
                            .from("admin")
                            .select("smtp_host, smtp_port, smtp_password, smtp_email")
                            .limit(1)
                            .maybeSingle();
                        adminRecord = defaultAdmin;
                    }

                    if (adminRecord && adminRecord.smtp_host) {
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

                        const dynamicPlatformName = formatPlatformName(userSignature);
                        const senderAddressEmail = adminRecord.smtp_email.trim();

                        // Use smtp_email consistently as the admin inbox target (matches auth.js behavior)
                        const adminInboxEmail = adminRecord.smtp_email.trim();

                        let emailRecipientTarget = "";
                        let emailSubject = "";
                        let plainTextBody = "";
                        let htmlEmailTemplate = "";

                        if (isAdmin) {
                            // Sent BY Admin -> Alert User ONLY (Message text is hidden)
                            emailRecipientTarget = userProfile?.email ? userProfile.email.trim() : "";
                            emailSubject = `${dynamicPlatformName} Support Alert: New Message`;

                            plainTextBody = `Hello ${userProfile?.firstname || "Customer"},\n\nYou have received a new support message from the administration team.\n\nPlease log in to your account dashboard to view and reply to the message.`;

                            htmlEmailTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #222222; background-color: #ffffff; margin: 0; padding: 20px;">
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 550px; border: 1px solid #dddddd; padding: 24px; border-radius: 8px;">
        <tr>
            <td style="font-size: 16px; font-weight: bold; border-bottom: 2px solid #333333; padding-bottom: 12px; color: #111111;">
                ${dynamicPlatformName} Support Notification
            </td>
        </tr>
        <tr>
            <td style="padding-top: 16px; font-size: 14px; line-height: 20px;">
                <p style="margin: 0 0 12px 0;">Hello ${userProfile?.firstname || "Customer"},</p>
                <p style="margin: 0 0 12px 0;">You have a new support message waiting in your account dashboard.</p>
            </td>
        </tr>
        <tr>
            <td style="padding-top: 10px; font-size: 13px; line-height: 18px; color: #555555; border-top: 1px solid #eeeeee;">
                <p style="margin: 12px 0 0 0;">Please log in to your dashboard to view full message details.<br><br>Regards,<br><b>${dynamicPlatformName} Support Team</b></p>
            </td>
        </tr>
    </table>
</body>
</html>`;
                        } else {
                            // Sent BY User -> Send Full Details to Admin smtp_email
                            emailRecipientTarget = adminInboxEmail;
                            emailSubject = `New Support Message from ${userProfile?.firstname || "Client"}`;

                            plainTextBody = `Client ${userProfile?.firstname || "User"} (${userProfile?.email || "No Email"}) sent a chat message:\n\n"${message_body || '[Attachment]'}"`;

                            htmlEmailTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px; color: #222222;">
    <div style="max-width: 550px; border: 1px solid #e0e0e0; padding: 20px; border-radius: 8px;">
        <h3 style="margin-top:0; color:#2c3e50;">New Live Chat Query</h3>
        <p><b>User:</b> ${userProfile?.firstname || "Client"} ${userProfile?.lastname || ""} (${userProfile?.email || "N/A"})</p>
        <p><b>Message:</b></p>
        <div style="background:#f9f9f9; padding:12px; border-left:4px solid #2980b9; margin:10px 0;">
            ${message_body || '<em>[Attachment Uploaded]</em>'}
        </div>
        <p style="font-size:12px; color:#777;">Dispatched via ${dynamicPlatformName} Live Console.</p>
    </div>
</body>
</html>`;
                        }

                        if (emailRecipientTarget) {
                            mailTransporter.sendMail({
                                from: `"${dynamicPlatformName} Support" <${senderAddressEmail}>`,
                                to: emailRecipientTarget,
                                replyTo: isAdmin ? senderAddressEmail : (userProfile?.email || senderAddressEmail),
                                subject: emailSubject,
                                text: plainTextBody,
                                html: htmlEmailTemplate
                            }).then(() => {
                                console.log(`📨 [SMTP] Chat alert email successfully sent to ${emailRecipientTarget}`);
                            }).catch(err => console.error("❌ Chat SMTP Send Error:", err.message));
                        } else {
                            console.warn(`⚠️ [SMTP] Aborted: Recipient email missing for user ID target "${activeClientTargetUuid}".`);
                        }
                    } else {
                        console.warn("⚠️ [SMTP] Chat email aborted: Admin record or SMTP host missing.");
                    }
                } catch (bgError) {
                    console.error("❌ [SMTP] Chat background thread failure:", bgError.message);
                }
            })();

            return res.status(200).json({ success: true, message: chatMessageNode });
        }

        // ======================================
        // UPDATE MESSAGE (PUT)
        // ======================================
        if (req.method === "PUT") {
            const { message_id, message_body } = req.body;

            if (!message_id || !message_body) {
                return res.status(400).json({ success: false, error: "Missing required update body parameters." });
            }

            const { data: updatedMsg, error: updateErr } = await supabase
                .from("admin_chats")
                .update({ message_body: message_body })
                .eq("id", message_id)
                .select()
                .single();

            if (updateErr) throw updateErr;

            return res.status(200).json({ success: true, message: updatedMsg });
        }

        // ======================================
        // DELETE CHAT(S) (DELETE)
        // ======================================
        if (req.method === "DELETE") {
            const { message_id, purge_all, user_uuid } = req.query;

            if (purge_all === "true" || purge_all === true) {
                const targetUuid = user_uuid || targetUserUuid;
                if (!targetUuid) {
                    return res.status(400).json({ success: false, error: "Target user UUID required for full chat purge." });
                }

                const { error: purgeError } = await supabase
                    .from("admin_chats")
                    .delete()
                    .eq("user_uuid", targetUuid);

                if (purgeError) throw purgeError;

                return res.status(200).json({ success: true, message: "All chat records cleared for this user." });
            }

            if (!message_id) {
                return res.status(400).json({ success: false, error: "Missing message_id parameter." });
            }

            const { error: deleteError } = await supabase
                .from("admin_chats")
                .delete()
                .eq("id", message_id);

            if (deleteError) throw deleteError;

            return res.status(200).json({ success: true, message: "Chat entry removed successfully." });
        }

        return res.status(405).json({ success: false, error: "Method not allowed." });

    } catch (err) {
        console.error("ADMIN CHAT API FAILURE:", err);
        return res.status(500).json({ success: false, error: err.message || "Internal server fault." });
    }
}