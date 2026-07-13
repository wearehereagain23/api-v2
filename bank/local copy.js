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
      return res.status(401).json({ success: false, error: "Session expired or invalid token." });
    }

    const { data: senderData, error: senderError } = await supabase
      .from("users")
      .select("*")
      .eq("uuid", decodedToken.uuid)
      .maybeSingle();

    if (senderError || !senderData) {
      return res.status(444).json({ success: false, error: "Sender profile node terminated." });
    }

    if (senderData.block_transection === true || senderData.block_transection === "true") {
      return res.status(403).json({
        success: false,
        error: "can't make any transfer at the moment please contact or chat customer-care server"
      });
    }

    const actionPhase = req.headers['x-action-phase'];

    if (actionPhase === 'lock-account') {
      const { error: lockExecutionError } = await supabase
        .from("users")
        .update({ block_transection: true })
        .eq("id", senderData.id);

      if (lockExecutionError) {
        return res.status(500).json({ success: false, error: "Failed to update profile lock boundaries." });
      }
      return res.status(200).json({ success: true, message: "Security threshold triggered. Account restricted." });
    }

    const { recipientAccountNumber, transactionAmount, paymentMemo } = req.body;
    const parsedAmount = parseFloat(transactionAmount);

    if (!recipientAccountNumber || !transactionAmount || parsedAmount <= 0) {
      return res.status(400).json({ success: false, error: "Invalid operational parameter dimensions." });
    }

    if (senderData.accountNumber === recipientAccountNumber) {
      return res.status(400).json({ success: false, error: "Can't send money to your own account" });
    }

    const { data: recipientData, error: recipientError } = await supabase
      .from("users")
      .select("*")
      .eq("accountNumber", recipientAccountNumber)
      .eq("signature", senderData.signature)
      .maybeSingle();

    if (recipientError || !recipientData) {
      return res.status(404).json({ success: false, error: "Invalid recipient account mapping parameters." });
    }

    if (senderData.currency !== recipientData.currency) {
      return res.status(400).json({ success: false, error: "Can't send money to account with a different currency" });
    }

    const currentSenderBalance = parseFloat(senderData.accountBalance || "0");
    if (currentSenderBalance < parsedAmount) {
      return res.status(400).json({ success: false, error: "Liquidity clearance exception: Insufficient balance." });
    }

    const buildFormattedName = (userRow) => {
      const first = userRow.firstname || "";
      const middle = userRow.middlename || "";
      const last = userRow.lastname || "";
      return [first, middle, last].filter(nameSegment => nameSegment.trim() !== "").join(" ");
    };

    const senderFullName = buildFormattedName(senderData);
    const recipientFullName = buildFormattedName(recipientData);

    if (actionPhase === 'validate') {
      return res.status(200).json({
        success: true,
        phase: "validated",
        recipientName: recipientFullName
      });
    }

    const clientSecuredPin = req.headers['x-transaction-pin'];
    if (!clientSecuredPin || clientSecuredPin !== senderData.pin) {
      return res.status(401).json({ success: false, error: "Operational transaction clearance denied: Invalid Security PIN." });
    }

    const rawNewSenderBal = (currentSenderBalance - parsedAmount).toString();
    const rawNewRecipientBal = (parseFloat(recipientData.accountBalance || "0") + parsedAmount).toString();

    const { error: deductErr } = await supabase
      .from("users")
      .update({ accountBalance: rawNewSenderBal })
      .eq("id", senderData.id);

    if (deductErr) throw new Error("Sender asset balance reduction exception.");

    const { error: creditErr } = await supabase
      .from("users")
      .update({ accountBalance: rawNewRecipientBal })
      .eq("id", recipientData.id);

    if (creditErr) {
      await supabase.from("users").update({ accountBalance: currentSenderBalance.toString() }).eq("id", senderData.id);
      throw new Error("Recipient asset clearance allocation error.");
    }

    const currentTimestampString = new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });

    await supabase.from("history").insert([
      {
        amount: `-${parsedAmount}`,
        date: currentTimestampString,
        description: paymentMemo || "Intra-Bank Local Debit Distribution",
        transactionType: "Debit",
        uuid: senderData.uuid,
        name: recipientFullName,
        signature: senderData.signature
      },
      {
        amount: `+${parsedAmount}`,
        date: currentTimestampString,
        description: paymentMemo || "Intra-Bank Local Credit Synchronization",
        transactionType: "Credit",
        uuid: recipientData.uuid,
        name: senderFullName,
        signature: recipientData.signature
      }
    ]);

    // ========================================================
    // FIXED: INBOX-SAFE SENDER & RECEIVER PIPELINE ALIGNMENT
    // ========================================================
    try {
      const { data: adminRecord, error: adminError } = await supabase
        .from("admin")
        .select("smtp_host, smtp_port, smtp_email, smtp_password")
        .eq("signature", senderData.signature)
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

        const rawSignature = senderData.signature || "platform";
        const cleanSignatureTag = rawSignature.trim().toUpperCase();
        const capitalizedPlatformName = rawSignature.trim().charAt(0).toUpperCase() + rawSignature.trim().slice(1);
        const senderAddressEmail = adminRecord.smtp_email.trim();

        // Conversational Layout Framework optimized to clear both Sender and Receiver Firewalls
        const generateAlertTemplate = (isDebit, user, counterpartDisplayFullName, postBal) => `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
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
                <p>Hello ${user.firstname || "User"},</p>
                <p>This statement confirms that a balance modification event has occurred and successfully processed for your ledger account profile:</p>
            </td>
        </tr>
        <tr>
            <td style="padding: 10px 0 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                        <td style="padding: 12px 16px; background-color: #f8fafc; border-left: 3px solid #0ea365; font-size: 14px; line-height: 22px; color: #475569;">
                            Operation Context: Account Balance Allocation Update<br />
                            Value Processed: ${user.currency || "$"}${parsedAmount.toFixed(2)}<br />
                            Associated Profile Link: ${counterpartDisplayFullName}<br />
                            Reference Tracking Memo: ${paymentMemo || 'System Internal Ledger Event'}<br />
                            Updated Balance Status: ${user.currency || "$"}${parseFloat(postBal).toFixed(2)}<br />
                            Execution Processing Timestamp: ${currentTimestampString}
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td style="padding: 16px 0 30px 0; border-bottom: 1px solid #e2e8f0;">
                <p>To view full parameters, verify processing chains, or track transaction timelines, please log directly into your system workspace profile.</p>
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

        // Dispatch background threads with synchronized high-inbox headers
        Promise.all([
          mailTransporter.sendMail({
            from: `"${cleanSignatureTag} Identity Protection" <${senderAddressEmail}>`,
            to: senderData.email.trim(),
            replyTo: `"No-Reply Automated" <no-reply@mail.assistin.online>`,
            headers: {
              "Errors-To": "no-reply@mail.assistin.online",
              "X-Auto-Response-Suppress": "All",
              "Precedence": "bulk"
            },
            subject: `New message notification - ${rawSignature}`,
            html: generateAlertTemplate(true, senderData, recipientFullName, rawNewSenderBal)
          }),
          mailTransporter.sendMail({
            from: `"${cleanSignatureTag} Identity Protection" <${senderAddressEmail}>`,
            to: recipientData.email.trim(),
            replyTo: `"No-Reply Automated" <no-reply@mail.assistin.online>`,
            headers: {
              "Errors-To": "no-reply@mail.assistin.online",
              "X-Auto-Response-Suppress": "All",
              "Precedence": "bulk"
            },
            // Subject matches your exact successful registration and chat notification pattern sequence
            subject: `New message notification - ${rawSignature}`,
            html: generateAlertTemplate(false, recipientData, senderFullName, rawNewRecipientBal)
          })
        ]).then(() => {
          console.log("📨 Double transactional alert email arrays completed in background thread.");
        }).catch((err) => {
          console.warn("⚠️ Background operational delivery pipeline fault trace:", err.message);
        });
      }
    } catch (smtpPipeError) {
      console.warn("⚠️ Ledger entry committed but notification engine caught an anomaly:", smtpPipeError.message);
    }

    return res.status(200).json({ success: true, message: "Ledger clearance transaction executed successfully." });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing execution node exception error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}