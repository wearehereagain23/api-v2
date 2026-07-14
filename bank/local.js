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

// Premium HTML Receipt Template Generator - Spam Optimized
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
          <p style="margin: 5px 0 0 0; font-size: 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">Activity Update</p>
        </div>

        <div style="padding: 40px 30px;">
          
          <div style="text-align: center; margin-bottom: 30px;">
            <span style="font-size: 14px; color: #64748b; font-weight: 600; text-transform: uppercase;">Amount ${isDebit ? 'Transferred' : 'Delivered'}</span>
            <h1 style="margin: 10px 0; font-size: 38px; font-weight: 800; color: #0f172a;">${amountText}</h1>
            <div style="display: inline-block; background-color: #ecfdf5; color: ${statusColor}; font-size: 12px; font-weight: 700; padding: 6px 16px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px;">
              ${status}
            </div>
          </div>

          <h3 style="margin: 0 0 15px 0; font-size: 14px; color: #0f172a; font-weight: 700; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px; text-transform: uppercase;">
            Update Specifications
          </h3>
          
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 30px;">
            <tr style="height: 35px;">
              <td style="color: #64748b;">Reference ID</td>
              <td style="text-align: right; color: #0f172a; font-weight: 600; font-family: monospace; font-size: 13px;">${referenceId}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Timestamp</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${dateString}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Action Class</td>
              <td style="text-align: right; color: ${isDebit ? '#ef4444' : '#10b981'}; font-weight: 600;">${isDebit ? 'Outgoing' : 'Incoming'}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">${isDebit ? 'Recipient' : 'Sender'}</td>
              <td style="text-align: right; color: #0f172a; font-weight: 600;">${isDebit ? recipientName : senderName}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Allocation Channel</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${accountSourceLabel}</td>
            </tr>
          </table>

          <h3 style="margin: 0 0 15px 0; font-size: 14px; color: #0f172a; font-weight: 700; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px; text-transform: uppercase;">
            Summary Details
          </h3>
          
          <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
            <tr style="height: 35px;">
              <td style="color: #64748b;">Principal Value</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${amountText}</td>
            </tr>
            <tr style="height: 35px;">
              <td style="color: #64748b;">Network Processing Fee</td>
              <td style="text-align: right; color: #0f172a; font-weight: 500;">${taxText}</td>
            </tr>
            <tr style="height: 45px; border-top: 2px solid #f1f5f9;">
              <td style="color: #0f172a; font-weight: 700; font-size: 15px;">Total Activity Value</td>
              <td style="text-align: right; color: ${accentColor}; font-weight: 800; font-size: 18px;">${totalText}</td>
            </tr>
          </table>

          <div style="background-color: #f8fafc; border-radius: 8px; border: 1px dashed #cbd5e1; padding: 15px; text-align: center; margin-top: 35px;">
            <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5;">
              If you did not authorize this action or suspect profile mismatch, please access your profile dashboard immediately to secure your credentials and communicate the reference ID above to our services.
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

    // Gracefully ignore legacy front-end post-transfer email request hooks
    if (action === "send_debit_email") {
      return res.status(200).json({ success: true, message: "Emails already handled inside transaction lifecycle." });
    }

    const baseAmount = parseFloat(amount) || 0;

    if (!accountNumber || baseAmount <= 0 || !balanceSource || !signature) {
      return res.status(400).json({ success: false, error: "Bad Request: Incomplete transfer properties." });
    }

    // ========================================================
    // PIPELINE RETRIEVAL: LOAD SENDER, RECIPIENT, AND SETTINGS
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

    // Return the calculated data instantly if this is just a transaction confirmation preview dry-run
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

    // ========================================================
    // DATABASE LEDGER UPDATE (DEBIT SENDER & CREDIT RECIPIENT)
    // ========================================================
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

    // Create history logs
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

    // Insert database notifications
    await supabase.from("notifications").insert([
      { user_id: senderData.uuid, title: "Local Transfer Issued", message: `Sent ${baseAmount} ${senderSymbol} from ${uiWithdrawLabel}. Tax: ${independentTaxValue} ${senderSymbol}.`, status: "unread" },
      { user_id: recipientData.uuid, title: "Local Funds Deposited", message: `Received ${recipientCreditAmount} ${recipientSymbol} from ${senderFullName}.`, status: "unread" }
    ]);

    // ========================================================
    // NODEMAILER ENGINE: SEND DEBIT AND CREDIT SIMULTANEOUSLY (DYNAMIC SMTP)
    // ========================================================
    if (adminConfig.smtp_host && adminConfig.smtp_email && adminConfig.smtp_password) {
      try {
        const mailTransporter = nodemailer.createTransport({
          host: adminConfig.smtp_host.trim(),
          port: parseInt(adminConfig.smtp_port, 10) || 465,
          secure: parseInt(adminConfig.smtp_port, 10) === 465, // TLS for 465, fallback starttls for 587
          auth: {
            user: adminConfig.smtp_email.trim(),
            pass: adminConfig.smtp_password.trim()
          }
        });

        const senderAddressEmail = adminConfig.smtp_email.trim();
        const cleanSignatureTag = String(platformLabel).replace(/[^a-zA-Z0-9 ]/g, "");

        // Generate dynamic Unique Transaction reference IDs
        const debitRefId = `TXN-${Math.floor(100000 + Math.random() * 900000)}-DEB`;
        const creditRefId = `TXN-${Math.floor(100000 + Math.random() * 900000)}-CRE`;

        // 1. Prepare Outgoing Receipt for Sender
        const debitHtml = generateReceiptHtml({
          brandName: cleanSignatureTag,
          recipientName: receiverFullName,
          senderName: senderFullName,
          transactionType: "Debit",
          amountText: `${senderSymbol}${baseAmount.toFixed(2)}`,
          taxText: `${senderSymbol}${independentTaxValue.toFixed(2)}`,
          totalText: `${senderSymbol}${totalSenderDeduction.toFixed(2)}`,
          dateString: formattedDateString,
          referenceId: debitRefId,
          accountSourceLabel: uiWithdrawLabel
        });

        // 2. Prepare Incoming Receipt for Recipient
        const creditHtml = generateReceiptHtml({
          brandName: cleanSignatureTag,
          recipientName: receiverFullName,
          senderName: senderFullName,
          transactionType: "Credit",
          amountText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          taxText: `${recipientSymbol}0.00`,
          totalText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          dateString: formattedDateString,
          referenceId: creditRefId,
          accountSourceLabel: "Account Balance"
        });

        // Execute concurrent dispatching with clean email priority headers
        await Promise.all([
          mailTransporter.sendMail({
            from: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
            to: senderData.email.trim(),
            replyTo: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
            subject: `Debit Notification: Transfer receipt ${debitRefId}`,
            html: debitHtml,
            headers: {
              "MIME-Version": "1.0",
              "X-Mailer": "Nodemailer",
              "X-Priority": "1", // High Priority delivery flag
              "Importance": "high"
            }
          }),
          mailTransporter.sendMail({
            from: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
            to: recipientData.email.trim(),
            replyTo: `"${cleanSignatureTag}" <${senderAddressEmail}>`,
            subject: `Credit Notification: Funds deposited ${creditRefId}`,
            html: creditHtml,
            headers: {
              "MIME-Version": "1.0",
              "X-Mailer": "Nodemailer",
              "X-Priority": "1", // High Priority delivery flag
              "Importance": "high"
            }
          })
        ]);
        console.log("📨 Symmetrical transactional receipts dispatch complete via Nodemailer SMTP.");

      } catch (nodemailerErr) {
        console.warn("⚠️ SMTP Dynamic dispatch failed. Trace details:", nodemailerErr.message);
      }
    } else {
      console.warn("⚠️ Transaction completed successfully, but dynamic SMTP coordinates are not active in the configuration database.");
    }

    return res.status(200).json({ success: true, message: "Ledger clearance transaction executed successfully." });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing execution error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}