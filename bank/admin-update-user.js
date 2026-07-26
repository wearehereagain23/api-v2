import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import ws from "ws";

const supabase = createClient(process.env.PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
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

    try {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Missing or malformed authorization token." });
        }

        const token = authHeader.split(" ")[1];
        try {
            jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtErr) {
            return res.status(401).json({ success: false, error: `Authentication Failed: ${jwtErr.message}` });
        }

        if (req.method !== "POST" && req.method !== "PUT") {
            return res.status(405).json({ success: false, error: "Method blocked." });
        }

        const targetId = req.body.id || req.query.id;
        const targetUuid = req.body.uuid || req.query.uuid;

        if (!targetId && !targetUuid) {
            return res.status(400).json({ success: false, error: "Target User ID or UUID is required." });
        }

        // Build update object dynamically to prevent overwriting missing fields with null/undefined/false
        const updateData = {};

        // String & General Fields
        const fields = [
            "accountBalance", "accountTypeBalance", "firstname", "middlename", "lastname",
            "email", "password", "pin", "accountNumber", "currency", "COT", "IMF", "TAX",
            "accttype", "address", "city", "country", "phone", "zipcode", "dateOfBirth",
            "gender", "occupation", "kinname", "tiers", "fixedDate"
        ];

        fields.forEach(field => {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
        });

        // Profile Image Fields
        if (req.body.profileImage !== undefined) updateData.profileImage = req.body.profileImage;
        if (req.body.image !== undefined && !updateData.profileImage) updateData.profileImage = req.body.image;

        // Numeric Fields
        if (req.body.tax_fee !== undefined && req.body.tax_fee !== null) {
            updateData.tax_fee = Number(req.body.tax_fee);
        }

        // Boolean Fields (Only set if explicitly provided in body)
        if (req.body["2fa"] !== undefined) {
            updateData["2fa"] = req.body["2fa"] === "true" || req.body["2fa"] === true;
        }
        if (req.body.block_transection !== undefined) {
            updateData.block_transection = req.body.block_transection === "true" || req.body.block_transection === true;
        }
        if (req.body.restricted !== undefined) {
            updateData.restricted = req.body.restricted === "true" || req.body.restricted === true;
        }
        if (req.body.transferAccess !== undefined) {
            updateData.transferAccess = req.body.transferAccess === "true" || req.body.transferAccess === true;
        }
        if (req.body.activeuser !== undefined) {
            updateData.activeuser = req.body.activeuser === "true" || req.body.activeuser === true;
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ success: false, error: "No update parameters provided in request body." });
        }

        // Build Supabase update query
        let query = supabase.from("users").update(updateData);

        if (targetId) {
            query = query.eq("id", targetId);
        } else {
            query = query.eq("uuid", targetUuid);
        }

        const { data: updatedRecord, error } = await query.select().single();

        if (error) throw error;

        return res.status(200).json({
            success: true,
            message: "User matrix profile synchronized completely.",
            user: updatedRecord
        });

    } catch (err) {
        console.error("❌ Admin User Profile Update Exception:", err.message);
        return res.status(500).json({ success: false, error: err.message });
    }
}