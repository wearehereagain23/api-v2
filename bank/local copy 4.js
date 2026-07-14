/**
 * ==========================================================================
 * ONFLEX LOCAL TRANSFER MATRIX CONTROLLER
 * Handles balance cards, preview modals, dynamic taxes, and secure PIN workflows.
 * ==========================================================================
 */
document.addEventListener("DOMContentLoaded", async () => {
  const BACKEND_DATA_URL = "https://api-v2-red.vercel.app/api/data";
  const BACKEND_TRANSFER_URL = "https://api-v2-red.vercel.app/api/local";
  const GLOBAL_PIN_URL = "https://api-v2-red.vercel.app/api/card-action";

  const rawSession = localStorage.getItem("user_session");
  if (!rawSession) {
    window.location.href = "../login/index.html";
    return;
  }
  const session = JSON.parse(rawSession);

  // Form DOM Elements matching local.html structure
  const transferForm = document.getElementById("transferForm");
  const balanceSelect = document.getElementById("withdrawFrom");
  const accountInput = document.getElementById("accountNumber");
  const amountInput = document.getElementById("amount");

  // Matrix Cards DOM Elements
  const mainBalanceHero = document.getElementById("accountBalance");
  const typeBalanceHero = document.getElementById("accountTypeBalance");
  const loanBalanceHero = document.getElementById("loanBalanace");
  const accountTypeLabel = document.getElementById("accounttype");
  const loanTypeLabel = document.getElementById("loantp");

  // Profile Details DOM Elements
  const profileName = document.getElementById("profileName");
  const profileAccount = document.getElementById("profileAccount");
  const accountLevel = document.getElementById("accountLevel");
  const accountLevel2 = document.getElementById("accountLevel2");
  const profileTypeDisplay = document.getElementById("profileTypeDisplay");

  let cachedUserRecord = null;

  /**
   * STAGE 1: INITIAL COMPONENT INITIALIZATION & BALANCE RENDER MATRIX
   */
  async function populateDashboardMetrics() {
    try {
      const syncCheck = await fetch(BACKEND_DATA_URL, {
        method: "GET",
        headers: { "Authorization": `Bearer ${session.token}` }
      });
      const syncData = await syncCheck.json();

      if (syncCheck.ok && syncData.success) {
        cachedUserRecord = syncData.data;
        const user = cachedUserRecord;

        // Read symbols directly from database definitions
        const symbol = user.currency || "$";

        // Profile card rendering
        if (profileName) profileName.innerText = `${user.firstname || ""} ${user.lastname || ""}`.trim() || "Active Client";
        if (profileAccount) profileAccount.innerText = user.accountNumber || "Unavailable";
        if (accountLevel) accountLevel.innerText = user.tiers;
        if (accountLevel2) accountLevel2.innerText = user.tiers;
        if (profileTypeDisplay) profileTypeDisplay.innerText = `${user.accttype || "Standard"} Node`;

        // Format values securely
        if (mainBalanceHero) mainBalanceHero.innerText = `${symbol}${parseFloat(user.accountBalance || 0).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;
        if (typeBalanceHero) typeBalanceHero.innerText = `${symbol}${parseFloat(user.accountTypeBalance || 0).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;
        if (loanBalanceHero) loanBalanceHero.innerText = `${symbol}${parseFloat(user.loanAmount || 0).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;

        if (accountTypeLabel) accountTypeLabel.innerText = user.accttype || "Savings";
        if (loanTypeLabel) loanTypeLabel.innerText = user.loanApprovalStatus === "Approved" ? "Active " : "Pending ";
      }
    } catch (err) {
      console.error("❌ Matrix rendering framework exception:", err);
    }
  }

  await populateDashboardMetrics();

  if (!transferForm) return;

  /**
   * STAGE 2: PREVIEW UI & TRANSACTION VALIDATION PIPELINE
   */
  transferForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const uiSelection = balanceSelect.value;
    let databaseBalanceColumn = "accountBalance";
    if (uiSelection === "accountType") databaseBalanceColumn = "accountTypeBalance";
    if (uiSelection === "loan") databaseBalanceColumn = "loanAmount";

    const recipientAccount = String(accountInput.value).trim();
    const typedAmount = parseFloat(amountInput.value) || 0;

    if (!recipientAccount || typedAmount <= 0) {
      Swal.fire({
        title: "Validation Error",
        text: "Please provide a valid destination account number and a positive transfer value.",
        icon: "error",
        background: "#111115",
        color: "#fff",
        confirmButtonColor: "#0a698f"
      });
      return;
    }

    if (databaseBalanceColumn === "accountTypeBalance" && cachedUserRecord?.fixedDate) {
      Swal.fire({
        title: "Withdrawal Unavailable",
        text: "This flexible vault allocation is locked under fixed maturity structural limitations.",
        icon: "warning",
        background: "#111115",
        color: "#fff",
        confirmButtonColor: "#0a698f"
      });
      return;
    }

    // 🌟 STEP A: Show Spinner while calling server to retrieve confirmation parameters
    Swal.fire({
      title: "Fetching Transfer Details...",
      text: "Verifying receiving endpoint context and computing dynamic exchange parameters.",
      background: "#111115",
      color: "#fff",
      didOpen: () => Swal.showLoading(),
      allowOutsideClick: false
    });

    let previewDetails = null;
    try {
      const previewResponse = await fetch(BACKEND_TRANSFER_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${session.token}`
        },
        body: JSON.stringify({
          accountNumber: recipientAccount,
          amount: typedAmount,
          balanceSource: databaseBalanceColumn,
          signature: "onflex",
          isPreview: true // Dry-run validation
        })
      });

      const previewData = await previewResponse.json();
      if (!previewResponse.ok || !previewData.success) {
        throw new Error(previewData.error || "Execution failed.");
      }
      previewDetails = previewData.data;
    } catch (err) {
      Swal.fire({
        title: "Verification Failed",
        text: err.message,
        icon: "error",
        background: "#111115",
        color: "#fff",
        confirmButtonColor: "#e74c3c"
      });
      return;
    }

    // 🌟 STEP B: Build HTML Preview Matrix dynamically
    const {
      recipientName,
      senderSymbol,
      recipientSymbol,
      baseAmount,
      taxApplied,
      totalDeduction,
      recipientCredit,
      exchangeRate,
      currenciesMatch
    } = previewDetails;

    let previewHtml = `
            <div style="text-align: left; font-family: sans-serif; color: #fff; padding: 10px;">
                <p style="margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 6px;">
                    <strong>Beneficiary:</strong> <span style="color: #2ecc71; float: right;">${recipientName}</span>
                </p>
                <p style="margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 6px;">
                    <strong>Transfer Value:</strong> <span style="float: right;">${senderSymbol}${baseAmount}</span>
                </p>
        `;

    if (!currenciesMatch) {
      previewHtml += `
                <p style="margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 6px; color: #ff9f43;">
                    <strong>Conversion Rate:</strong> <span style="float: right;">1 ${senderSymbol} = ${exchangeRate} ${recipientSymbol}</span>
                </p>
                <p style="margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 6px; color: #2ecc71;">
                    <strong>Recipient Receives:</strong> <span style="float: right; font-weight: bold;">${recipientSymbol}${recipientCredit}</span>
                </p>
                <p style="margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 6px; color: #e74c3c;">
                    <strong>Processing Tax:</strong> <span style="float: right;">${senderSymbol}${taxApplied}</span>
                </p>
                <p style="margin-bottom: 4px; font-size: 1.1rem;">
                    <strong>Total Debit Amount:</strong> <span style="color: #e74c3c; font-weight: bold; float: right;">${senderSymbol}${totalDeduction}</span>
                </p>
            `;
    } else {
      previewHtml += `
                <p style="margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 6px; color: #2ecc71;">
                    <strong>Tax Fee:</strong> <span style="float: right; color: #2ecc71; font-weight: bold;">${senderSymbol}0.00</span>
                </p>
                <p style="margin-bottom: 4px; font-size: 1.1rem;">
                    <strong>Total Debit Amount:</strong> <span style="color: #2ecc71; font-weight: bold; float: right;">${senderSymbol}${baseAmount}</span>
                </p>
            `;
    }

    previewHtml += `</div>`;

    // 🌟 STEP C: Render Custom Confirmation Window
    const confirmResult = await Swal.fire({
      title: "Confirm Transaction",
      html: previewHtml,
      icon: "info",
      background: "#111115",
      color: "#fff",
      showCancelButton: true,
      confirmButtonColor: "#0a698f",
      cancelButtonColor: "#222",
      confirmButtonText: "Proceed to Authorization",
      cancelButtonText: "Modify Details"
    });

    if (!confirmResult.isConfirmed) return;

    // STAGE 3: LAUNCH UNIFIED SECURITY PIN OVERLAY
    const authenticationChallenge = await OnFlexAuth.verifyPin(
      GLOBAL_PIN_URL,
      session.user?.id || session.user?.uuid || cachedUserRecord?.uuid,
      "onflex",
      session.token
    );

    if (!authenticationChallenge || !authenticationChallenge.success) {
      return;
    }

    // STAGE 4: SUBMIT FULL LIVE LEDGER SETTLEMENT
    Swal.fire({
      title: "Processing Local Transfer...",
      text: "Executing ledger changes and creating dynamic notification entries.",
      background: "#111115",
      color: "#fff",
      didOpen: () => Swal.showLoading(),
      allowOutsideClick: false
    });

    try {
      const response = await fetch(BACKEND_TRANSFER_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${session.token}`
        },
        body: JSON.stringify({
          accountNumber: recipientAccount,
          amount: typedAmount,
          balanceSource: databaseBalanceColumn,
          signature: "onflex",
          isPreview: false // Commit live ledger write
        })
      });

      const result = await response.json();

      if (response.ok && result.success) {
        // ========================================================
        // POST-SUCCESS HOOK: DISPATCH SENDER DEBIT NOTIFICATION
        // ========================================================
        fetch(BACKEND_TRANSFER_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${session.token}`
          },
          body: JSON.stringify({
            accountNumber: recipientAccount,
            amount: typedAmount,
            balanceSource: databaseBalanceColumn,
            signature: "onflex",
            action: "send_debit_email" // Triggers intercepted sender mail alert pipeline
          })
        }).catch(err => console.warn("⚠️ Post-transaction debit mail hook failed:", err));

        Swal.fire({
          title: "Transfer Complete",
          text: result.message || "Ledger adjustment completed successfully.",
          icon: "success",
          background: "#111115",
          color: "#fff",
          confirmButtonColor: "#0a698f"
        }).then(() => {
          transferForm.reset();
          window.location.reload();
        });
      } else {
        Swal.fire({
          title: "Transaction Failure",
          text: result.error || "The routing node rejected this operation context request.",
          icon: "error",
          background: "#111115",
          color: "#fff",
          confirmButtonColor: "#e74c3c"
        });
      }
    } catch (error) {
      Swal.fire({
        title: "Network Exception",
        text: "Unable to reach the centralized clearings node array.",
        icon: "error",
        background: "#111115",
        color: "#fff",
        confirmButtonColor: "#e74c3c"
      });
    }
  });
});

function pro() {
  window.location.href = "profile.html";
}