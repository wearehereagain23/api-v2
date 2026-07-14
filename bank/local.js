import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import ws from "ws";
import { getIsoCode } from "./currency.js";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  realtime: { transport: ws }
});

// Premium HTML Receipt Template Generator
function generateReceiptHtml({
  brandName,
  recipientName,
  transactionType, // "Debit" or "Credit"
  amountText,
  taxText,
  totalText,
  dateString,
  senderName,
  referenceId,
  accountSourceLabel,
  status = "Successful"
}) {
  const isDebit = transactionType.toLowerCase() === "debit";
  const statusColor = "#10b981"; // Green for successful
  const accentColor = "#0a698f"; // OnFlex Theme Blue

  return `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8fafc; padding: 40px 15px; margin: 0; min-height: 100%;">
      <div style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -1px rgba(0,0,0,0.03); border: 1px solid #e2e8f0; overflow: hidden;">
        
        <div style="background-color: #0f172a; padding: 30px; text-align: center; color: #ffffff;">
          <h2 style="margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">${brandName}</h2>
          <p style="margin: 5px 0 0 0; font-size: 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">Transaction Receipt</p>
        </div>

        <div style="padding: 40px 30px;">
          
          <div style="text-align: center; margin-bottom: 30px;">
            <span style="font-size: 14px; color: #64748b; font-weight: 600; text-transform: uppercase;">Amount ${isDebit ? 'Sent' : 'Received'}</span>
            <h1 style="margin: 10px 0; font-size: 38px; font-weight: 800; color: #0f172a;">${amountText}</h1>
            <div style="display: inline-block; background-color: #ecfdf5; color: ${statusColor}; font-size: 12px; font-weight: 700; padding: 6px 16px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px;">
              ${status}
            </div>
          </div>

          <h3 style="margin: 0 0 15px 0; font-size: 14px; color: #0f172a; font-weight: 700; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px; text-transform: uppercase;">
            Transaction Details
          </h3>
          
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 30px;">
            <tr style="height: 35px;">
              <td style="color: #64748b;">Reference ID</td>
              <td style="text-align: right; color: #0f172a; font-weight: 600; font-family: monospace; font-size: 13px;">${referenceId}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Date</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${dateString}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Transaction Type</td>
              <td style="text-align: right; color: ${isDebit ? '#ef4444' : '#10b981'}; font-weight: 600;">${transactionType}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">${isDebit ? 'Recipient' : 'Sender'}</td>
              <td style="text-align: right; color: #0f172a; font-weight: 600;">${isDebit ? recipientName : senderName}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Source Asset Pool</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${accountSourceLabel}</td>
            </tr>
          </table>

          <h3 style="margin: 0 0 15px 0; font-size: 14px; color: #0f172a; font-weight: 700; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px; text-transform: uppercase;">
            Financial Impact Summary
          </h3>
          
          <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
            <tr style="height: 35px;">
              <td style="color: #64748b;">Base Principal</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${amountText}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Routing Fees / Tax</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${taxText}</td>
            </tr>
            <tr style="height: 45px; border-top: 2px solid #f1f5f9;">
              <td style="color: #0f172a; font-weight: 700; font-size: 15px;">Total Impact Value</td>
              <td style="text-align: right; color: ${accentColor}; font-weight: 800; font-size: 18px;">${totalText}</td>
            </tr>
          </table>

          <div style="background-color: #f8fafc; border-radius: 8px; border: 1px dashed #cbd5e1; padding: 15px; text-align: center; margin-top: 35px;">
            <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5;">
              If you did not authorize this action or suspect fraudulent activities on your account node, please secure your profile immediately and escalate this trace reference ID to our support channels.
            </p>
          </div>

        </div>

        <div style="background-color: #f8fafc; padding: 24px; text-align: center; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8;">
          <p style="margin: 0 0 4px 0;">This is an automated operational notification. Please do not reply directly to this mail routing agent.</p>
          <p style="margin: 0;">&copy; ${new Date().getFullYear()} ${brandName}. All rights reserved.</p>
        </div>
      </div>
    </div>
  `;
}

export default async function handler(req, res) {
  const requestOrigin = req.headers.origin;
  if (requestOrigin) {
    res.setHeader("Access-Control-Allow-Origin", requestOrigin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ success: false, error: "Method blocked." });

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, error: "Access Denied: Auth context missing." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decodedClaims = jwt.verify(token, JWT_SECRET);
    const senderUuid = decodedClaims.uuid || decodedClaims.id || (decodedClaims.user && decodedClaims.user.id);

    if (!senderUuid) {
      return res.status(401).json({ success: false, error: "Unauthorized Identity verification." });
    }

    const { accountNumber, amount, balanceSource, signature, isPreview, action } = req.body;
    const baseAmount = parseFloat(amount) || 0;

    if (!accountNumber || baseAmount <= 0 || !balanceSource || !signature) {
      return res.status(400).json({ success: false, error: "Bad Request: Incomplete transfer properties." });
    }

    // ========================================================
    // PIPELINE INTERCEPTOR: DEDICATED SENDER DEBIT ALERT DISPATCH
    // ========================================================
    if (action === "send_debit_email") {
      const [senderRes, recipientRes, adminRes] = await Promise.all([
        supabase.from("users").select("*").eq("uuid", senderUuid).single(),
        supabase.from("users").select("*").eq("accountNumber", String(accountNumber).trim()).maybeSingle(),
        supabase.from("admin").select("*").eq("signature", signature).maybeSingle()
      ]);

      if (senderRes.error || !senderRes.data) return res.status(404).json({ success: false, error: "Sender profile missing." });
      const senderData = senderRes.data;

      if (!recipientRes.data) return res.status(404).json({ success: false, error: "Recipient profile missing." });
      const recipientData = recipientRes.data;

      const adminConfig = adminRes.data || {};
      const platformLabel = adminConfig.website_name || "OnFlex Finance";

      const formattedDateString = new Date().toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric"
      });

      const receiverFullName = `${recipientData.firstname || ""} ${recipientData.lastname || ""}`.trim();
      const senderSymbol = String(senderData.currency || "$").trim();

      // Recalculate fees precisely for receipt
      const currenciesMatch = (senderSymbol === String(recipientData.currency || "$").trim());
      const taxPercentage = currenciesMatch ? 0 : parseFloat(senderData.tax_fee !== undefined ? senderData.tax_fee : 3);
      const independentTaxValue = parseFloat((baseAmount * (taxPercentage / 100)).toFixed(2));
      const totalSenderDeduction = parseFloat((baseAmount + independentTaxValue).toFixed(2));

      let uiWithdrawLabel = "Account Balance";
      if (balanceSource === "accountTypeBalance") uiWithdrawLabel = senderData.accttype || "Fixed Vault Balance";
      if (balanceSource === "loanAmount") uiWithdrawLabel = "Loan Allocation";

      const referenceId = `TXN-${Math.floor(100000 + Math.random() * 900000)}-DEB`;

      try {
        if (adminConfig.smtp_host && adminConfig.smtp_email) {
          const mailTransporter = nodemailer.createTransport({
            host: adminConfig.smtp_host,
            port: parseInt(adminConfig.smtp_port, 10) || 465,
            secure: parseInt(adminConfig.smtp_port, 10) === 465,
            auth: { user: adminConfig.smtp_email, pass: adminConfig.smtp_password }
          });

          const senderAddressEmail = adminConfig.smtp_email.trim();
          const cleanSignatureTag = String(platformLabel).replace(/[^a-zA-Z0-9 ]/g, "");

          const receiptHtml = generateReceiptHtml({
            brandName: cleanSignatureTag,
            recipientName: receiverFullName,
            senderName: `${senderData.firstname} ${senderData.lastname}`,
            transactionType: "Debit",
            amountText: `${senderSymbol}${baseAmount.toFixed(2)}`,
            taxText: `${senderSymbol}${independentTaxValue.toFixed(2)}`,
            totalText: `${senderSymbol}${totalSenderDeduction.toFixed(2)}`,
            dateString: formattedDateString,
            referenceId: referenceId,
            accountSourceLabel: uiWithdrawLabel
          });

          await mailTransporter.sendMail({
            from: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
            to: senderData.email.trim(),
            replyTo: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
            subject: `Debit Notification: Transfer receipt ${referenceId}`,
            html: receiptHtml,
            headers: {
              "Errors-To": senderAddressEmail,
              "X-Auto-Response-Suppress": "All",
              "Precedence": "bulk"
            }
          });
          console.log("📨 Isolated sender debit notification completed successfully.");
        }
      } catch (smtpErr) {
        console.warn("⚠️ Sender isolated email tracking warning:", smtpErr.message);
      }

      return res.status(200).json({ success: true, message: "Debit alert dispatched successfully." });
    }

    // ========================================================
    // STANDARD ROUTE PIPELINE: PRIMARY TRANSACTION LOGIC
    // ========================================================
    const [senderRes, recipientRes, adminRes] = await Promise.all([
      supabase.from("users").select("*").eq("uuid", senderUuid).single(),
      supabase.from("users").select("*").eq("accountNumber", String(accountNumber).trim()).maybeSingle(),
      supabase.from("admin").select("*").eq("signature", signature).maybeSingle()
    ]);

    if (senderRes.error || !senderRes.data) return res.status(404).json({ success: false, error: "Sender profile missing." });
    const senderData = senderRes.data;

    if (senderData.block_transaction === true || senderData.block_transaction === "true") {
      return res.status(403).json({ success: false, error: "User is blocked from making transfer please contact customer care." });
    }

    if (senderData.restricted === true || senderData.activeuser === false) {
      return res.status(403).json({ success: false, error: "Account structure currently placed under restriction holds." });
    }

    if (!recipientRes.data) return res.status(404).json({ success: false, error: "Destination account parameters not recognized." });
    const recipientData = recipientRes.data;

    if (senderData.uuid === recipientData.uuid) {
      return res.status(400).json({ success: false, error: "Self-transfer parameters rejected within local routes." });
    }

    if (balanceSource === "loanAmount") {
      if (!senderData.loanApprovalStatus || String(senderData.loanApprovalStatus).trim() !== "Approved") {
        return res.status(403).json({
          success: false,
          error: "Withdrawal Denied: Access to the loan allocation matrix is locked until your application status is 'Approved'."
        });
      }
    }

    const adminConfig = adminRes.data || {};
    const platformLabel = adminConfig.website_name || "OnFlex Finance";

    const senderSymbol = String(senderData.currency || "$").trim();
    const recipientSymbol = String(recipientData.currency || "$").trim();
    const currenciesMatch = (senderSymbol === recipientSymbol);

    const taxPercentage = currenciesMatch ? 0 : parseFloat(senderData.tax_fee !== undefined ? senderData.tax_fee : 3);
    const independentTaxValue = parseFloat((baseAmount * (taxPercentage / 100)).toFixed(2));
    const totalSenderDeduction = parseFloat((baseAmount + independentTaxValue).toFixed(2));

    const senderAvailableBalance = parseFloat(senderData[balanceSource]) || 0;
    if (totalSenderDeduction > senderAvailableBalance) {
      return res.status(400).json({ success: false, error: "Insufficient liquidity core to cover transaction value and tax fees." });
    }

    let computationalExchangeRate = 1.0;
    let recipientCreditAmount = baseAmount;

    if (!currenciesMatch) {
      const senderCode = getIsoCode(senderSymbol);
      const recipientCode = getIsoCode(recipientSymbol);

      try {
        const responseFeed = await fetch(`https://open.er-api.com/v6/latest/${senderCode}`);
        if (!responseFeed.ok) throw new Error("API Node connection error.");

        const rateMapData = await responseFeed.json();
        const targetedCurrencyRate = rateMapData.rates[recipientCode];

        if (targetedCurrencyRate) {
          computationalExchangeRate = parseFloat(targetedCurrencyRate);
          recipientCreditAmount = parseFloat((baseAmount * computationalExchangeRate).toFixed(2));
        } else {
          throw new Error(`Target mapping symbol variant [${recipientCode}] not recognized on index.`);
        }
      } catch (err) {
        console.warn(`⚠️ Currency Engine Exception (${senderCode}->${recipientCode}):`, err.message);
        computationalExchangeRate = 1.0;
        recipientCreditAmount = baseAmount;
      }
    }

    if (isPreview === true || isPreview === "true") {
      return res.status(200).json({
        success: true,
        data: {
          recipientName: `${recipientData.firstname} ${recipientData.lastname}`,
          senderSymbol: senderSymbol,
          recipientSymbol: recipientSymbol,
          baseAmount: baseAmount.toFixed(2),
          taxApplied: independentTaxValue.toFixed(2),
          totalDeduction: totalSenderDeduction.toFixed(2),
          recipientCredit: recipientCreditAmount.toFixed(2),
          exchangeRate: computationalExchangeRate,
          currenciesMatch: currenciesMatch
        }
      });
    }

    const rawNewSenderBal = parseFloat((senderAvailableBalance - totalSenderDeduction).toFixed(2));
    const rawNewRecipientBal = parseFloat(((parseFloat(recipientData.accountBalance) || 0) + recipientCreditAmount).toFixed(2));

    const [senderUpdate, recipientUpdate] = await Promise.all([
      supabase.from("users").update({ [balanceSource]: rawNewSenderBal }).eq("uuid", senderData.uuid),
      supabase.from("users").update({ accountBalance: rawNewRecipientBal }).eq("uuid", recipientData.uuid)
    ]);

    if (senderUpdate.error) throw new Error(`Sender debit layer error: ${senderUpdate.error.message}`);
    if (recipientUpdate.error) throw new Error(`Recipient credit layer error: ${recipientUpdate.error.message}`);

    const formattedDateString = new Date().toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric"
    });

    const senderFullName = `${senderData.firstname || ""} ${senderData.lastname || ""}`.trim();
    const receiverFullName = `${recipientData.firstname || ""} ${recipientData.lastname || ""}`.trim();

    let uiWithdrawLabel = "Account Balance";
    if (balanceSource === "accountTypeBalance") uiWithdrawLabel = senderData.accttype || "Fixed Vault Balance";
    if (balanceSource === "loanAmount") uiWithdrawLabel = "Loan Allocation";

    const historyEntries = [
      {
        date: formattedDateString,
        amount: String(baseAmount.toFixed(2)),
        bankName: platformLabel,
        status: "Successful",
        withdrawFrom: uiWithdrawLabel,
        name: receiverFullName,
        description: `Local transfer issued to ${receiverFullName}`,
        transactionType: "Debit",
        uuid: senderData.uuid,
        signature: signature,
        tax_charge: String(independentTaxValue.toFixed(2))
      },
      {
        date: formattedDateString,
        amount: String(recipientCreditAmount.toFixed(2)),
        bankName: platformLabel,
        status: "Successful",
        withdrawFrom: "account balance",
        name: senderFullName,
        description: `Local funds deposited by ${senderFullName}`,
        transactionType: "Credit",
        uuid: recipientData.uuid,
        signature: signature,
        tax_charge: null
      }
    ];

    const historyInsert = await supabase.from("history").insert(historyEntries);
    if (historyInsert.error) {
      console.error("⚠️ History Ledger Error Trace:", historyInsert.error.message);
    }

    await supabase.from("notifications").insert([
      { user_id: senderData.uuid, title: "Local Transfer Issued", message: `Sent ${baseAmount} ${senderSymbol} from ${uiWithdrawLabel}. Tax: ${independentTaxValue} ${senderSymbol}.`, status: "unread" },
      { user_id: recipientData.uuid, title: "Local Funds Deposited", message: `Received ${recipientCreditAmount} ${recipientSymbol} from ${senderFullName}.`, status: "unread" }
    ]);

    // ========================================================
    // RECIPIENT SMTP ENGINE: CREDIT DISPATCH STRICTLY TARGETED
    // ========================================================
    const recipientRefId = `TXN-${Math.floor(100000 + Math.random() * 900000)}-CRE`;
    try {
      if (adminConfig.smtp_host && adminConfig.smtp_email) {
        const mailTransporter = nodemailer.createTransport({
          host: adminConfig.smtp_host,
          port: parseInt(adminConfig.smtp_port, 10) || 465,
          secure: parseInt(adminConfig.smtp_port, 10) === 465,
          auth: { user: adminConfig.smtp_email, pass: adminConfig.smtp_password }
        });

        const senderAddressEmail = adminConfig.smtp_email.trim();
        const cleanSignatureTag = String(platformLabel).replace(/[^a-zA-Z0-9 ]/g, "");

        const receiptHtml = generateReceiptHtml({
          brandName: cleanSignatureTag,
          recipientName: receiverFullName,
          senderName: senderFullName,
          transactionType: "Credit",
          amountText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          taxText: `${recipientSymbol}0.00`, // Recipients incur no conversion charges in their pool balance directly
          totalText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          dateString: formattedDateString,
          referenceId: recipientRefId,
          accountSourceLabel: "Account Balance"
        });

        await mailTransporter.sendMail({
          from: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
          to: recipientData.email.trim(),
          replyTo: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
          subject: `Credit Notification: Funds deposited ${recipientRefId}`,
          html: receiptHtml,
          headers: {
            "Errors-To": senderAddressEmail,
            "X-Auto-Response-Suppress": "All",
            "Precedence": "bulk"
          }
        });
        console.log("📨 Isolated recipient credit transactional mail delivery completed.");
      }
    } catch (e) {
      console.warn("⚠️ Email tracking delivery warning:", e.message);
    }

    return res.status(200).json({ success: true, message: "Ledger clearance transaction executed successfully." });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing execution error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}