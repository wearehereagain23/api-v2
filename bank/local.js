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

/**
 * ANTI-SPAM OPTIMIZED TRANSACTIONAL HTML TEMPLATE
 * Designed for maximum deliverability across Gmail, Outlook, Yahoo, and Apple Mail.
 */
function generateAntiSpamHtml({
  platformName,
  recipientName,
  transactionType, // "Debit" or "Credit"
  amountText,
  descriptionText,
  partyName,
  balanceText,
  dateString,
  isCrossCurrency = false,
  exchangeRateText = "",
  convertedAmountText = ""
}) {
  const isCredit = transactionType.toLowerCase() === "credit";
  const amountColor = isCredit ? "#0f766e" : "#b91c1c"; // Darker green/red pass spam filter contrast checks

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transaction Summary</title>
</head>
<body style="margin: 0; padding: 20px 0; background-color: #f4f5f7; font-family: Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f4f5f7;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 520px; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; margin: 20px auto;">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 24px 24px 12px 24px; border-bottom: 2px solid #2563eb;">
                            <h2 style="margin: 0; color: #1e293b; font-size: 20px; font-weight: bold; font-family: Arial, sans-serif;">${platformName}</h2>
                        </td>
                    </tr>
                    <!-- Body -->
                    <tr>
                        <td style="padding: 24px; color: #334155; font-size: 14px; line-height: 1.5;">
                            <p style="margin-top: 0; margin-bottom: 16px;">Dear ${recipientName},</p>
                            <p style="margin-top: 0; margin-bottom: 20px; color: #475569;">A recent transaction has processed on your account. Below are the details for your records:</p>
                            
                            <!-- Detail Card -->
                            <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 20px;">
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; color: #64748b; font-size: 13px;">Type</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #1e293b; font-weight: bold; font-size: 13px;">${transactionType}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; color: #64748b; font-size: 13px;">Amount</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; text-align: right; color: ${amountColor}; font-weight: bold; font-size: 15px;">${amountText}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; color: #64748b; font-size: 13px;">Description</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #334155; font-size: 13px;">${descriptionText || "N/A"}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; color: #64748b; font-size: 13px;">${isCredit ? "Sender" : "Recipient"}</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #1e293b; font-weight: 600; font-size: 13px;">${partyName}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; color: #64748b; font-size: 13px;">Available Balance</td>
                                    <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #0f172a; font-weight: bold; font-size: 13px;">${balanceText}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px 16px; ${isCrossCurrency ? "border-bottom: 1px solid #e2e8f0;" : ""} color: #64748b; font-size: 13px;">Date</td>
                                    <td style="padding: 12px 16px; ${isCrossCurrency ? "border-bottom: 1px solid #e2e8f0;" : ""} text-align: right; color: #334155; font-size: 13px;">${dateString}</td>
                                </tr>
                                ${isCrossCurrency ? `
                                <tr>
                                    <td style="padding: 12px 16px; color: #0284c7; font-size: 12px; font-weight: 600;">Conversion Details</td>
                                    <td style="padding: 12px 16px; text-align: right; color: #334155; font-size: 12px;">
                                        <strong>${convertedAmountText}</strong><br>
                                        <span style="color: #64748b;">Rate: ${exchangeRateText}</span>
                                    </td>
                                </tr>
                                ` : ""}
                            </table>

                            <p style="margin: 0; font-size: 12px; color: #64748b;">Thank you for banking with us.</p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 16px 24px; background-color: #f1f5f9; border-top: 1px solid #e2e8f0; text-align: center; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;">
                            <p style="margin: 0; font-size: 11px; color: #94a3b8;">This is an automated system receipt. Please do not reply directly to this email.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;
}

/**
 * PLAIN TEXT FALLBACK GENERATOR
 * Crucial for proving to inbox filters that this is a legitimate message.
 */
function generateAntiSpamText({ platformName, recipientName, transactionType, amountText, descriptionText, partyName, balanceText, dateString }) {
  return `${platformName} - Transaction Statement

Hello ${recipientName},

A transaction has processed on your account. Here are the details:

- Type: ${transactionType}
- Amount: ${amountText}
- Description: ${descriptionText || "N/A"}
- ${transactionType.toLowerCase() === "credit" ? "Sender" : "Recipient"}: ${partyName}
- Available Balance: ${balanceText}
- Date: ${dateString}

Thank you for banking with us.

--
${platformName} Automated Services`;
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

    const { accountNumber, amount, balanceSource, signature, isPreview, action, description } = req.body;

    if (action === "send_debit_email") {
      return res.status(200).json({ success: true, message: "Emails already handled inside transaction lifecycle." });
    }

    const baseAmount = parseFloat(amount) || 0;

    if (!accountNumber || baseAmount <= 0 || !balanceSource || !signature) {
      return res.status(400).json({ success: false, error: "Bad Request: Incomplete transfer properties." });
    }

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
    const platformLabel = adminConfig.website_name || "Assistin";

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
      month: "short",
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
        description: description,
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
        description: description,
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
    // OPTIMIZED INBOX-FRIENDLY SMTP BROADCAST ENGINE
    // ========================================================
    if (adminConfig.smtp_host && adminConfig.smtp_email && adminConfig.smtp_password) {
      try {
        const mailTransporter = nodemailer.createTransport({
          host: adminConfig.smtp_host.trim(),
          port: adminConfig.smtp_port,
          auth: {
            user: adminConfig.smtp_email.trim(),
            pass: adminConfig.smtp_password.trim()
          }
        });

        const smtpUserEmail = adminConfig.smtp_email.trim();
        const emailDomain = smtpUserEmail ? smtpUserEmail.split("@")[1] : "platform.com";
        const noReplyHeader = `"No-Reply Automated System" <no-reply@${emailDomain}>`;

        // 1. Debit Packet (Sender)
        const debitData = {
          platformName: platformLabel,
          recipientName: senderData.firstname || "Valued Customer",
          transactionType: "Debit",
          amountText: `-${senderSymbol}${totalSenderDeduction.toFixed(2)}`,
          descriptionText: description,
          partyName: receiverFullName,
          balanceText: `${senderSymbol}${rawNewSenderBal.toFixed(2)}`,
          dateString: formattedDateString,
          isCrossCurrency: !currenciesMatch,
          exchangeRateText: `1 ${senderSymbol} = ${computationalExchangeRate.toFixed(4)} ${recipientSymbol}`,
          convertedAmountText: `${recipientSymbol}${recipientCreditAmount.toFixed(2)}`
        };

        // 2. Credit Packet (Recipient)
        const creditData = {
          platformName: platformLabel,
          recipientName: recipientData.firstname || "Valued Customer",
          transactionType: "Credit",
          amountText: `+${recipientSymbol}${recipientCreditAmount.toFixed(2)}`,
          descriptionText: description,
          partyName: senderFullName,
          balanceText: `${recipientSymbol}${rawNewRecipientBal.toFixed(2)}`,
          dateString: formattedDateString,
          isCrossCurrency: !currenciesMatch,
          exchangeRateText: `1 ${senderSymbol} = ${computationalExchangeRate.toFixed(4)} ${recipientSymbol}`,
          convertedAmountText: `${senderSymbol}${baseAmount.toFixed(2)}`
        };

        await Promise.all([
          // Sender Mail
          mailTransporter.sendMail({
            from: `"${platformLabel}" <${smtpUserEmail}>`, // Match sender exactly to SMTP domain
            replyTo: noReplyHeader,
            to: senderData.email.trim(),
            subject: `Transaction Receipt: ${senderSymbol}${totalSenderDeduction.toFixed(2)} Debit`,
            text: generateAntiSpamText(debitData),
            html: generateAntiSpamHtml(debitData)
          }),
          // Recipient Mail
          mailTransporter.sendMail({
            from: `"${platformLabel}" <${smtpUserEmail}>`,
            replyTo: noReplyHeader,
            to: recipientData.email.trim(),
            subject: `Transaction Receipt: ${recipientSymbol}${recipientCreditAmount.toFixed(2)} Credit`,
            text: generateAntiSpamText(creditData),
            html: generateAntiSpamHtml(creditData)
          })
        ]);

        console.log("📨 Deliverability-optimized email receipts dispatched successfully.");

      } catch (nodemailerErr) {
        console.warn("⚠️ SMTP Dispatch failed. Trace details:", nodemailerErr.message);
      }
    }

    return res.status(200).json({ success: true, message: "Ledger clearance transaction executed successfully." });

  } catch (globalExecutionError) {
    console.error("❌ Local clearing execution error:", globalExecutionError);
    return res.status(500).json({ success: false, error: globalExecutionError.message });
  }
}