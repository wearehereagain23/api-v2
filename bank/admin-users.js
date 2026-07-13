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

    // UPDATED: Global method blocker removed to allow multi-method restful operations to process smoothly

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Administrative security clearance token missing or malformed." });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, JWT_SECRET);

        // ==========================================
        // METHOD: GET (RETRIEVE USER LOG RECOGNITION REGISTRY)
        // ==========================================
        if (req.method === "GET") {
            // Explicitly target the lowercase key string 
            const targetWorkspaceSignature = req.query.signature || req.headers["x-setting-target"];

            let queryBuilder = supabase
                .from("users")
                .select("*")
                .order("id", { ascending: false });

            // Apply strict isolation boundaries
            if (targetWorkspaceSignature && targetWorkspaceSignature.trim() !== "") {
                queryBuilder = queryBuilder.eq("signature", targetWorkspaceSignature.trim());
            } else {
                // Safe-fail fallback: If an admin endpoint doesn't identify the workspace context, block it
                return res.status(400).json({ success: false, error: "Required workspace signature parameter context missing from requests pipeline." });
            }

            const { data: usersData, error: dbError } = await queryBuilder;

            if (dbError) throw dbError;

            return res.status(200).json({
                success: true,
                users: usersData
            });
        }

        // ==========================================
        // METHOD: PUT (UPDATE DISPATCH LAYER ATTRIBUTES)
        // ==========================================
        if (req.method === "PUT") {
            const { id } = req.query;
            const updatedFields = req.body;

            if (!id) {
                return res.status(400).json({ success: false, error: "Missing required identifier parameter." });
            }

            const { data: updateData, error: updateError } = await supabase
                .from("users")
                .update(updatedFields)
                .eq("id", id)
                .select();

            if (updateError) throw updateError;

            return res.status(200).json({
                success: true,
                data: updateData
            });
        }

        // ==========================================
        // METHOD: DELETE (CASCADING EXCISION PURGE ROUTINE)
        // ==========================================
        if (req.method === "DELETE") {
            const { uuid } = req.query;

            if (!uuid) {
                return res.status(400).json({ success: false, error: "Target operational UUID criteria value parameters missing." });
            }

            // Sub-Routine 1: Drop matching references inside ledger settlement log grids
            const { error: historyDropErr } = await supabase
                .from("history")
                .delete()
                .eq("uuid", uuid);

            if (historyDropErr) throw new Error(`History sub-table drop routine error: ${historyDropErr.message}`);

            // Sub-Routine 2: Targeted user_uuid clean extraction mapping rule line
            const { error: chatDropErr } = await supabase
                .from("admin_chats")
                .delete()
                .eq("user_uuid", uuid);

            if (chatDropErr) throw new Error(`Admin chats support stream drop routine error: ${chatDropErr.message}`);

            // Sub-Routine 3: Drop primary credentials access context out of the root profile table rows
            const { error: finalProfilePurgeErr } = await supabase
                .from("users")
                .delete()
                .eq("uuid", uuid);

            if (finalProfilePurgeErr) throw new Error(`Users primary registration layer purge exception: ${finalProfilePurgeErr.message}`);

            return res.status(200).json({
                success: true,
                message: "Cradle-to-grave account data context matrices dropped completely out of records storage tracks logs configurations safely."
            });
        }

        return res.status(405).json({ success: false, error: "HTTP Target Action context block rejected." });

    } catch (error) {
        console.error("❌ Admin Users Core Operation Exception:", error.message);
        return res.status(500).json({ success: false, error: error.message });
    }
}