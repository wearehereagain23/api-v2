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

  if (req.method !== "POST") {
    return res.status(405).json({ success: false, error: "Method blocked." });
  }

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "Authentication credentials missing." });
    }

    const token = authHeader.split(" ")[1];
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (jwtErr) {
      return res.status(401).json({ success: false, error: "Session validation token expired." });
    }

    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("uuid", decodedToken.uuid)
      .maybeSingle();

    if (userError || !userData) {
      return res.status(444).json({ success: false, error: "Operator identity mapping failure." });
    }

    if (userData.block_transection === true || userData.block_transection === "true") {
      return res.status(403).json({
        success: false,
        error: "can't make any transfer at the moment please contact or chat customer-care server"
      });
    }

    const actionPhase = req.headers['x-action-phase'];

    if (actionPhase === 'lock-account') {
      await supabase.from("users").update({ block_transection: true }).eq("id", userData.id);
      return res.status(200).json({ success: true, message: "Security boundaries triggered. Account restricted." });
    }

    if (actionPhase === 'pre-check') {
      const { amount } = req.body;
      const requestedAmount = parseFloat(amount || "0");

      if (!requestedAmount || requestedAmount <= 0) {
        return res.status(400).json({ success: false, error: "Invalid operational transaction amount bounds." });
      }

      const userAvailableBalance = parseFloat(userData.accountBalance || "0");
      if (userAvailableBalance < requestedAmount) {
        return res.status(400).json({ success: false, error: "Liquidity clearance exception: Insufficient balance assets." });
      }

      return res.status(200).json({
        success: true,
        transferAccess: userData.transferAccess === true || userData.transferAccess === "true"
      });
    }

    if (actionPhase === 'verify-pin') {
      const userProvidedPin = req.body.pin ? String(req.body.pin).trim() : "";
      const databaseStoredPin = userData.pin ? String(userData.pin).trim() : "";
      return res.status(200).json({ success: userProvidedPin === databaseStoredPin });
    }

    if (actionPhase === 'verify-imf') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.IMF || userData.imf) ? String(userData.IMF || userData.imf).trim() : "";
      return res.status(200).json({ success: userProvidedCode === databaseStoredCode && databaseStoredCode !== "" });
    }

    if (actionPhase === 'verify-tax') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.TAX || userData.tax) ? String(userData.TAX || userData.tax).trim() : "";
      return res.status(200).json({ success: userProvidedCode === databaseStoredCode && databaseStoredCode !== "" });
    }

    if (actionPhase === 'verify-cot') {
      const userProvidedCode = req.body.code ? String(req.body.code).trim() : "";
      const databaseStoredCode = (userData.COT || userData.cot) ? String(userData.COT || userData.cot).trim() : "";
      return res.status(200).json({ success: userProvidedCode === databaseStoredCode && databaseStoredCode !== "" });
    }

    if (actionPhase === 'commit-transfer') {
      const clientSecuredPin = req.headers['x-transaction-pin'];
      if (!clientSecuredPin || clientSecuredPin !== userData.pin) {
        return res.status(401).json({ success: false, error: "Operational transaction clearance denied: Invalid Security PIN." });
      }

      const { amount, fullname, accountnumber, bankname, des } = req.body;
      const parsedAmount = parseFloat(amount);

      const currentBalance = parseFloat(userData.accountBalance || "0");
      if (currentBalance < parsedAmount) {
        return res.status(400).json({ success: false, error: "Balance liquidity exception validation fault." });
      }

      const updateBalanceValue = (currentBalance - parsedAmount).toString();

      const { error: deductErr } = await supabase
        .from("users")
        .update({ accountBalance: updateBalanceValue })
        .eq("id", userData.id);

      if (deductErr) throw new Error("Processing ledger debit structural rejection exception.");

      const timestampString = new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });

      await supabase.from("history").insert([
        {
          amount: `-${parsedAmount}`,
          date: timestampString,
          description: des || `Cross-Border SWIFT Wire: ${bankname}`,
          transactionType: "Debit",
          uuid: userData.uuid,
          name: fullname || `Beneficiary: ${accountnumber}`,
          signature: userData.signature
        }
      ]);

      // ==========================================
      // INBOX-SAFE TRANSACTION DELIVERY ALIGNMENT
      // ==========================================
      try {
        const { data: adminRecord, error: adminError } = await supabase
          .from("admin")
          .select("smtp_host, smtp_port, smtp_email, smtp_password")
          .eq("signature", userData.signature)
          .maybeSingle();

        if (!adminError && adminRecord) {
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

          const rawSignature = userData.signature || "platform";
          const cleanSignatureTag = rawSignature.trim().toUpperCase();
          const capitalizedPlatformName = rawSignature.trim().charAt(0).toUpperCase() + rawSignature.trim().slice(1);
          const senderAddressEmail = adminRecord.smtp_email.trim();

          // Conversational design framework matching your clean high-delivery parameters
          const templateLayout = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
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
                ${capitalizedPlatformName} System Desk Communication
            </td>
        </tr>
        <tr>
            <td style="padding: 24px 0 16px 0;">
                <p>Hello ${userData.firstname || "User"},</p>
                <p>This statement confirms that a cross-border wire operation transaction has been compiled matching your routing matrix attributes:</p>
            </td>
        </tr>
        <tr>
            <td style="padding: 10px 0 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                        <td style="padding: 12px 16px; background-color: #f8fafc; border-left: 3px solid #0ea365; font-size: 14px; line-height: 22px; color: #475569;">
                            Operation Type: International Wire Ledger Account Update<br />
                            Amount Processed: ${userData.currency || "$"}${parsedAmount.toFixed(2)}<br />
                            Target Destination Account: ${fullname} (${bankname})<br />
                            Reference Tracking Memo: ${des || 'Funds Wire Process Execution'}<br />
                            Updated Balance Status: ${userData.currency || "$"}${parseFloat(updateBalanceValue).toFixed(2)}<br />
                            Execution Processing Timestamp: ${timestampString}
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding: 16px 0 30px 0; border-bottom: 1px solid #e2e8f0;">
                <p>To access full core parameters, adjust configurations, or review histories, please log directly into your system workspace profile.</p>
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

          mailTransporter.sendMail({
            from: `"${cleanSignatureTag} Identity Protection" <${senderAddressEmail}>`,
            to: userData.email.trim(),
            replyTo: `"No-Reply Automated" <no-reply@mail.assistin.online>`,
            headers: {
              "Errors-To": "no-reply@mail.assistin.online",
              "X-Auto-Response-Suppress": "All",
              "Precedence": "bulk"
            },
            subject: `New message notification - ${rawSignature}`,
            html: templateLayout
          }).then(() => {
            console.log("📨 Transaction update email dispatched safely into background thread.");
          }).catch((err) => {
            console.warn("⚠️ Background message thread exception recorded:", err.message);
          });
        }
      } catch (smtpPipeError) {
        console.warn("⚠️ Notification stream bypassed safely:", smtpPipeError.message);
      }

      return res.status(200).json({ success: true, message: "Cross-border transaction execution finalized." });
    }

  } catch (globalExecutionError) {
    console.error("❌ International handler root loop error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}