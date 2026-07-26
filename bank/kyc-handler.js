import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";

// 1. SYSTEM ENVIRONMENT INITIALIZATION
const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
    throw new Error("CRITICAL CONFIGURATION ERROR: Supabase or JWT credential mappings are unassigned inside environment properties.");
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

/**
 * Controller Route Handler Engine for Account Identification Verification Documents Processing (KYC)
 */
export default async function kycVerificationHandler(req, res) {
    // A. CORS & OPTION METHOD INTERCEPTORS
    const requestOrigin = req.headers.origin;
    if (requestOrigin) res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-setting-target");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

    // B. AUTHENTICATION & SECURITY VALIDATION LAYERS
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, error: "Access Denied: Security framework headers context missing." });
    }

    const token = authHeader.split(" ")[1];
    let decodedClaims;
    try {
        decodedClaims = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ success: false, error: "Session token expired or corrupted." });
    }

    const verifiedUuid = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);
    const signature = decodedClaims.signature || "onflex";

    if (!verifiedUuid) {
        return res.status(401).json({ success: false, error: "Identity decryption validation dropped." });
    }

    const dynamicPlatformName = formatPlatformName(signature);

    // C. EXTRACT WORKFLOW DEPLOYMENT PAYLOAD PARAMETERS
    const {
        occupation,
        marital_status,
        phone,
        zipcode,
        address,
        kinname,
        kin_email,
        signature: clientSignature,
        kyc_image1,
        kyc_image2,
        kyc_image3
    } = req.body;

    if (!kyc_image1 || !kyc_image2 || !kyc_image3) {
        return res.status(400).json({ success: false, error: "Required structural verification asset matrix data fields missing." });
    }

    try {
        // 1. Fetch Dynamic SMTP Engine Credentials directly from the admin workspace matching signature
        const { data: adminRecord, error: adminError } = await supabase
            .from("admin")
            .select("smtp_host, smtp_port, smtp_password, smtp_email, website_name")
            .eq("signature", signature)
            .maybeSingle();

        if (adminError || !adminRecord) {
            return res.status(500).json({ success: false, error: "Administrative network workspace profile parsing exception fault." });
        }

        const platformLabel = adminRecord.website_name || dynamicPlatformName;

        // 2. Fetch target user record
        const { data: userRecord, error: userError } = await supabase
            .from("users")
            .select("email, firstname, lastname")
            .eq("uuid", verifiedUuid)
            .maybeSingle();

        if (userError || !userRecord) {
            return res.status(444).json({ success: false, error: "Target account identity matrix parameters lookup returned null references." });
        }

        // 3. Processing upload routines to primary Cloud Asset buckets
        const uploadBase64ToStorage = async (base64Str, nameMarker) => {
            const buffer = Buffer.from(base64Str, 'base64');
            const targetPath = `kyc/${verifiedUuid}_${nameMarker}_${Date.now()}.png`;

            const { error: uploadErr } = await supabase.storage
                .from('profileimages')
                .upload(targetPath, buffer, { contentType: 'image/png', upsert: true });

            if (uploadErr) throw uploadErr;

            return supabase.storage.from('profileimages').getPublicUrl(targetPath).data.publicUrl;
        };

        const [urlId, urlBill, urlFace] = await Promise.all([
            uploadBase64ToStorage(kyc_image1, 'id'),
            uploadBase64ToStorage(kyc_image2, 'bill'),
            uploadBase64ToStorage(kyc_image3, 'face')
        ]);

        // 4. Build data injection synchronization properties map (MATCHING DB EXACT COLUMN CASING)
        const updatePayload = {
            occupation,
            marital_status,
            phone,
            zipcode,
            address,
            kinname,
            kin_email,
            kyc: 'pending',
            "KYC_image1": urlId,    // Uppercase mapped to match DB schema
            "KYC_image2": urlBill,  // Uppercase mapped to match DB schema
            "KYC_image3": urlFace   // Uppercase mapped to match DB schema
        };

        // Synchronize table modifications natively matching target primary uuid key match bounds
        const { error: dbError } = await supabase
            .from('users')
            .update(updatePayload)
            .eq('uuid', verifiedUuid);

        if (dbError) throw dbError;

        // D. FIRE BACKGROUND SMTP TRANSMISSION ENGINE USING CAPTURED DB TOKENS
        try {
            const mailTransporter = nodemailer.createTransport({
                host: adminRecord.smtp_host,
                port: adminRecord.smtp_port,
                auth: {
                    user: adminRecord.smtp_email,
                    pass: adminRecord.smtp_password
                }
            });

            const emailDomain = adminRecord.smtp_email ? adminRecord.smtp_email.split("@")[1] : "platform.com";
            const noReplyHeader = `"No-Reply Automated System" <no-reply@${emailDomain}>`;

            const clientSubject = `[Verification Received] KYC Documents Under Review - ${platformLabel}`;
            const adminSubject = `🚨 [KYC SUBMISSION ALERT] New Account Verification Request`;

            const clientHtmlBody = `
                <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: #0b0b0e; padding: 40px 20px;">
                    <div style="max-width: 560px; margin: 0 auto; background: #111115; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; overflow: hidden; box-shadow: 0 8px 24px rgba(0,0,0,0.3);">
                        <div style="background: #0a698f; padding: 24px; text-align: center;">
                            <h2 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 600; letter-spacing: 0.5px;">Identity Verification Under Review</h2>
                        </div>
                        <div style="padding: 30px; color: #e2e8f0; line-height: 1.6; font-size: 14px;">
                            <p style="margin-top: 0; font-size: 15px;">Hello ${userRecord.firstname || "User"},</p>
                            <p style="color: #94a3b8;">Your Know Your Customer (KYC) documentation has been successfully submitted and is currently undergoing compliance review.</p>
                            
                            <div style="background: rgba(255, 255, 255, 0.02); padding: 20px; border-radius: 8px; margin: 24px 0; border: 1px solid rgba(255, 255, 255, 0.06);">
                                <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);"><td style="padding: 10px 0; color: #94a3b8;">Occupation:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #ffffff;">${occupation}</td></tr>
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);"><td style="padding: 10px 0; color: #94a3b8;">Phone Number:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #ffffff;">${phone}</td></tr>
                                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);"><td style="padding: 10px 0; color: #94a3b8;">Address:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #ffffff;">${address}</td></tr>
                                    <tr><td style="padding: 10px 0; color: #94a3b8;">Verification Status:</td><td style="text-align: right; padding: 10px 0; font-weight: 600; color: #f59e0b;">Pending Review</td></tr>
                                </table>
                            </div>
                            
                            <p style="color: #8a99ad; font-size: 0.85rem; text-align: center; margin-bottom: 0; margin-top: 25px;">Our compliance unit typically processes verification requests shortly. You will be notified once approved.</p>
                            <p style="font-size: 11px; color: #888888; text-align: center; margin-top: 15px;">This is an automated notification. Please do not reply directly to this email.</p>
                        </div>
                    </div>
                </div>`;

            const adminHtmlBody = `
                <div style="font-family: Arial, sans-serif; background: #f8fafc; color: #0f172a; padding: 30px; border-radius: 8px; max-width: 600px; margin: 20px auto; border: 1px solid #e2e8f0;">
                    <h3 style="color: #0f172a; border-bottom: 2px solid #cbd5e1; padding-bottom: 10px; margin-top:0;">${platformLabel} Core Security Hub System Monitor Alert</h3>
                    <p><b>Operational Action Event Frame:</b> KYC_DOCUMENTS_SUBMITTED</p>
                    <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px;">
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold; width:40%;">Account Holder Reference:</td><td style="padding: 8px;">${userRecord.firstname} ${userRecord.lastname}</td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">User Account Mapping Email:</td><td style="padding: 8px;">${userRecord.email}</td></tr>
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold;">System Scope UUID:</td><td style="padding: 8px; font-family: monospace;">${verifiedUuid}</td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">Occupation:</td><td style="padding: 8px;">${occupation}</td></tr>
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold;">Next of Kin:</td><td style="padding: 8px;">${kinname} (${kin_email})</td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">Government ID Proof:</td><td style="padding: 8px;"><a href="${urlId}" target="_blank">View Document</a></td></tr>
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold;">Utility Bill Proof:</td><td style="padding: 8px;"><a href="${urlBill}" target="_blank">View Document</a></td></tr>
                        <tr><td style="padding: 8px; font-weight: bold;">Biometric Face Scan:</td><td style="padding: 8px;"><a href="${urlFace}" target="_blank">View Snapshot</a></td></tr>
                        <tr style="background: #f1f5f9;"><td style="padding: 8px; font-weight: bold;">State Verification Token:</td><td style="padding: 8px; font-weight: bold; color: #f59e0b;">Pending Review</td></tr>
                    </table>
                    <p style="margin-top: 25px; font-size: 0.85rem; color: #64748b;">Log into your master administration console to review and approve or reject this verification application.</p>
                </div>`;

            await Promise.all([
                mailTransporter.sendMail({
                    from: `"${platformLabel}" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: userRecord.email,
                    subject: clientSubject,
                    html: clientHtmlBody
                }),
                mailTransporter.sendMail({
                    from: `"${platformLabel} System Core Monitor" <${adminRecord.smtp_email}>`,
                    replyTo: noReplyHeader,
                    to: adminRecord.smtp_email.trim(),
                    subject: adminSubject,
                    html: adminHtmlBody
                })
            ]);

            console.log("📨 KYC interaction transaction reporting emails successfully routed.");
        } catch (mailThreadError) {
            console.warn("⚠️ Intermittent mail subsystem tracking loop warning:", mailThreadError.message);
        }

        return res.status(200).json({ success: true, message: "KYC profile submission tracked completely under review." });

    } catch (globalExecutionFault) {
        console.error("❌ Global transaction thread logic failure:", globalExecutionFault);
        return res.status(500).json({ success: false, error: globalExecutionFault.message || "Internal database routing network fault." });
    }
}