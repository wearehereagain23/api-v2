import "dotenv/config";
import express from "express";
import cors from "cors";

// ==========================================
// 1. CORE FUNCTIONAL MODULE IMPORTS
// ==========================================
import checkHandler from "./bank/check.js";
import dataHandler from "./bank/data.js";
import authHandler from "./bank/auth.js";
import historyHandler from "./bank/history.js";
import settingsHandler from "./bank/settings.js";
import profileHandler from "./bank/profile.js";
import localHandler from "./bank/local.js";
import internationalHandler from "./bank/international.js";
import avatarHandler from "./bank/avatar.js";

// Administrative Console Modules
import adminAuthHandler from "./bank/admin-auth.js";
import adminUsersHandler from "./bank/admin-users.js";
import adminUpdateUserHandler from "./bank/admin-update-user.js";
import adminHistoryHandler from "./bank/admin-history.js";
import adminChatHandler from "./bank/admin-chat.js";
import adminAiHistoryHandler from "./bank/admin-ai-history.js";
import adminSettingsProfileHandler from "./bank/admin-settings-profile.js";

import cardHandler from "./bank/card.js";

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// 2. CENTRALIZED CORS ENGINE MANAGEMENT
// ==========================================
app.use(cors({
    // Setting origin to true dynamically reads the origin from the request header and echoes it back.
    // This allows multiple frontends/websites to access the API seamlessly without hardcoded whitelists.
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "X-Action",
        "X-Action-Phase",
        "x-action-phase",
        "X-Transaction-Pin",
        "X-User-UUID",
        "X-Setting-Target",
        "x-setting-target"
    ]
}));

// ==========================================
// 3. MIDDLEWARE & STREAM ROUTING ROUTINES
// ==========================================

// Intercept file-upload handling paths before json parses raw stream data strings
const multipartRoutes = ["/bank/profile", "/bank/avatar"];

app.use((req, res, next) => {
    if (multipartRoutes.includes(req.path)) {
        return next(); // Skip parsing json body parameters on raw multimedia uploads
    }
    express.json()(req, res, next);
});

app.use((req, res, next) => {
    if (multipartRoutes.includes(req.path)) {
        return next();
    }
    express.urlencoded({ extended: true })(req, res, next);
});

// ==========================================
// 4. SERVERLESS ADAPTOR LAYERING MATRIX
// ==========================================
const adaptHandler = (serverlessHandler) => {
    return async (req, res) => {
        try {
            // Re-map express parameters to match Next.js Serverless properties expected by functions
            req.query = { ...req.query, ...req.params };

            // Standardize status method function binding
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

// Primary Ledger Core Routing Modules
app.all("/api/check", adaptHandler(checkHandler));
app.all("/api/data", adaptHandler(dataHandler));
app.post("/bank/auth", adaptHandler(authHandler));  // <-- This fixes the endpoint configuration crash
app.all("/api/history", adaptHandler(historyHandler));
app.all("/api/settings", adaptHandler(settingsHandler));
app.all("/api/local", adaptHandler(localHandler));
app.all("/api/international", adaptHandler(internationalHandler));
app.all("/api/card-action", adaptHandler(cardHandler));
// Profile Asset Storage Modules
app.all("/api/profile", adaptHandler(profileHandler));
app.all("/api/avatar", adaptHandler(avatarHandler));

// Administrative Console Matrix Actions
app.all("/api/admin-auth", adaptHandler(adminAuthHandler));
app.all("/api/admin-users", adaptHandler(adminUsersHandler));
app.all("/api/admin-update-user", adaptHandler(adminUpdateUserHandler));
app.all("/api/admin-history", adaptHandler(adminHistoryHandler));
app.all("/api/admin-chat", adaptHandler(adminChatHandler));
app.all("/api/admin-ai-history", adaptHandler(adminAiHistoryHandler));
app.all("/api/admin-settings-profile", adaptHandler(adminSettingsProfileHandler));

// ==========================================
// 6. HEALTH MONITORS & BOOT STRAPPER
// ==========================================
app.get("/", (req, res) => {
    res.status(200).json({ status: "online", system: "Core Ledger Engine", platform: "Node-Express Continuous Matrix Instance" });
});

app.listen(PORT, () => {
    console.log(`\n===============================================================`);
    console.log(`🚀 CORE ENGINE RUNNING CLEANLY AT: http://localhost:${PORT}`);
    console.log(`🛠️ TOTAL ACTIVE CONNECTED HANDLERS INTERFACED: 16`);
    console.log(`===============================================================\n`);
});