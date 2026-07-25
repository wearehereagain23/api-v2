import "dotenv/config";
import express from "express";
import cors from "cors";
import webpush from "web-push";

// ==========================================
// 1. CORE FUNCTIONAL MODULE IMPORTS
// ==========================================
import checkHandler from "./bank/check.js";
import dataHandler from "./bank/data.js";
import historyHandler from "./bank/history.js";
import settingsHandler from "./bank/settings.js";
import profileHandler from "./bank/profile.js";
import localHandler from "./bank/local.js";
import internationalHandler from "./bank/international.js";
import avatarHandler from "./bank/avatar.js";

import notificationSetupHandler from "./bank/notification-setup.js";
import kycVerificationHandler from "./bank/kyc-handler.js";

// Administrative Console Modules
import adminAuthHandler from "./bank/admin-auth.js";
import adminUsersHandler from "./bank/admin-users.js";
import adminUpdateUserHandler from "./bank/admin-update-user.js";
import adminHistoryHandler from "./bank/admin-history.js";
import adminChatHandler from "./bank/admin-chat.js";
import adminAiHistoryHandler from "./bank/admin-ai-history.js";
import adminSettingsProfileHandler from "./bank/admin-settings-profile.js";
import loanActionHandler from "./bank/loan-action.js";

import adminApprovalHandler from "./bank/admin-approval.js";

import cardHandler from "./bank/card.js";

import deleteAccountHandler from './bank/user-delete.js';

import twoFactorAuthHandler from './bank/2fa.js';

import notificationSystemHandler from "./bank/notification-system.js";

import registerUserHandler from "./bank/register-user.js";
import loginUserHandler from "./bank/login-user.js";
import adminSettingsHandler from "./bank/admin-settings.js";
import verifyPinHandler from "./bank/verify-pin.js";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ==========================================
// 1b. WEB-PUSH VAPID KEY SETUP
// ==========================================
const publicVapidKey = process.env.PUBLIC_VAPID_KEY;
const privateVapidKey = process.env.PRIVATE_VAPID_KEY;

if (publicVapidKey && privateVapidKey) {
    webpush.setVapidDetails(
        "mailto:security@onflex-premium.com",
        publicVapidKey,
        privateVapidKey
    );
} else {
    console.warn("⚠️ Warning: Web-Push VAPID keys are missing from environment variables.");
}

// ==========================================
// 2. CENTRALIZED CORS ENGINE MANAGEMENT
// ==========================================
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        callback(null, true);
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], // Added PATCH
    allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "X-Action",
        "X-Action-Phase",
        "x-action-phase",
        "X-Transaction-Pin",
        "x-transaction-pin",
        "X-User-UUID",
        "X-Setting-Target",
        "x-setting-target",
        "X-Signature",
        "x-signature",
        "x-user-uuid",
        'X-Access-Token'
    ],
    credentials: true,
    optionsSuccessStatus: 200
}));

app.options("*", cors());

// ==========================================
// 4. SERVERLESS ADAPTOR LAYERING MATRIX
// ==========================================
const adaptHandler = (serverlessHandler) => {
    return async (req, res) => {
        try {
            req.query = { ...req.query, ...req.params };

            if (!res.status) {
                res.status = (statusCode) => {
                    res.statusCode = statusCode;
                    return res;
                };
            }

            await serverlessHandler(req, res);
        } catch (error) {
            console.error(`❌ Global Gateway Exception on Route [${req.path}]:`, error);
            if (!res.headersSent) {
                res.status(500).json({ success: false, error: error.message || "Internal Service Connectivity Fault." });
            }
        }
    };
};

// ==========================================
// 5. ROUTE SYSTEM DISPATCH COUPLING MATRIX
// ==========================================

// VAPID Public Key Delivery Endpoint for PWA Subscription Setup
app.get("/api/vapidPublicKey", (req, res) => {
    if (!publicVapidKey) {
        return res.status(500).json({ success: false, error: "VAPID key signatures not configured on server runtime." });
    }
    res.status(200).json({ key: publicVapidKey });
});

// Primary Ledger Core Routing Modules
app.all("/api/check", adaptHandler(checkHandler));
app.all("/api/data", adaptHandler(dataHandler));
app.all("/api/history", adaptHandler(historyHandler));

// Smart Route Branching Matrix for Settings Path Variations
app.all("/api/settings", async (req, res) => {
    const targetHeader = req.headers["x-setting-target"] || req.headers["X-Setting-Target"];

    if (targetHeader === "notifications") {
        return adaptHandler(notificationSetupHandler)(req, res);
    }

    if (targetHeader === "kyc") {
        return adaptHandler(kycVerificationHandler)(req, res);
    }

    return adaptHandler(settingsHandler)(req, res);
});

app.all("/api/local", adaptHandler(localHandler));
app.all("/api/international", adaptHandler(internationalHandler));
app.all("/api/card-action", adaptHandler(cardHandler));

// Profile Asset Storage Modules
app.all("/api/profile", adaptHandler(profileHandler));
app.all("/api/avatar", adaptHandler(avatarHandler));

app.all("/api/loan-action", adaptHandler(loanActionHandler));

// Administrative Console Matrix Actions
app.all("/api/admin-auth", adaptHandler(adminAuthHandler));
app.all("/api/admin-users", adaptHandler(adminUsersHandler));
app.all("/api/admin-history", adaptHandler(adminHistoryHandler));
app.all("/api/admin-chat", adaptHandler(adminChatHandler));
app.all("/api/admin-ai-history", adaptHandler(adminAiHistoryHandler));
app.all("/api/admin-settings-profile", adaptHandler(adminSettingsProfileHandler));

app.post('/api/2fa', twoFactorAuthHandler);
app.delete('/api/user-delete', deleteAccountHandler);

app.post("/api/admin-approval", adminApprovalHandler);
app.all("/api/admin-update-user", adaptHandler(adminUpdateUserHandler));

app.all("/api/notifications", adaptHandler(notificationSystemHandler));
app.all("/api/notifications/read", adaptHandler(notificationSystemHandler));
app.post("/bank/register-user", registerUserHandler);
app.post("/bank/login-user", loginUserHandler);
app.all("/api/admin-settings", adaptHandler(adminSettingsHandler));
app.all("/api/verify-pin", adaptHandler(verifyPinHandler));

// ==========================================
// 6. HEALTH MONITORS & BOOT STRAPPER
// ==========================================
app.get("/", (req, res) => {
    res.status(200).json({ status: "online", system: "Core Ledger Engine", platform: "Node-Express Continuous Matrix Instance" });
});

app.listen(PORT, () => {
    console.log(`\n===============================================================`);
    console.log(`🚀 CORE ENGINE RUNNING CLEANLY AT: http://localhost:${PORT}`);
    console.log(`🛠️ TOTAL ACTIVE CONNECTED HANDLERS INTERFACED: 17`);
    console.log(`===============================================================\n`);
});