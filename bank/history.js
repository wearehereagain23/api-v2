import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

export default async function handler(req, res) {
    // Setup CORS structures
    const requestOrigin = req.headers.origin;
    if (requestOrigin) {
        res.setHeader("Access-Control-Allow-Origin", requestOrigin);
    }

    // 2. Allow all HTTP methods your handlers use
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // 3. Explicitly allow all your specific custom app headers
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Action, X-Action-Phase, X-Transaction-Pin, X-User-UUID, X-Setting-Target, x-setting-target");

    // 4. Keep your credentials authentication layer active
    res.setHeader("Access-Control-Allow-Credentials", "true");

    // Handle preflight options request immediately
    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    // UPDATED: Changed from !== "POST" to !== "GET" to process front-end queries seamlessly on Vercel
    if (req.method !== "GET") {
        return res.status(405).json({ success: false, error: "Method blocked." });
    }

    try {
        // Validate authentication pipeline headers
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Access credentials reference missing." });
        }

        const token = authHeader.split(" ")[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (jwtErr) {
            return res.status(401).json({ success: false, error: "Operational user session session expired." });
        }

        // Step 1: Validate active user account context mapping matches
        const { data: userData, error: userError } = await supabase
            .from("users")
            .select("uuid")
            .eq("uuid", decodedToken.uuid)
            .maybeSingle();

        if (userError || !userData) {
            return res.status(444).json({ success: false, error: "Security context account mapping anomaly detected." });
        }

        // Step 2: Query historical transaction logs matching the owner's explicit uuid pointer string
        const { data: historyLogs, error: historyError } = await supabase
            .from("history")
            .select("*")
            .eq("uuid", userData.uuid)
            .order("id", { ascending: false }); // Sorts by primary sequence id to guarantee newest item matches are listed first

        if (historyError) {
            throw new Error(historyError.message);
        }

        return res.status(200).json({
            success: true,
            message: "Ledger historical records extracted successfully.",
            data: historyLogs || []
        });

    } catch (err) {
        console.error("❌ History Root Engine Processing Anomaly:", err.message);
        return res.status(500).json({ success: false, error: "Internal ledger processing server node layout failure exception." });
    }
}