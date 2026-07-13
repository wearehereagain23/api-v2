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

export const config = {
    api: {
        bodyParser: false
    }
};

export default async function handler(req, res) {
    // Universal CORS Matrix Configuration
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

    // UPDATED: Global method check removed to allow the endpoint to properly parse custom multi-part form requests

    try {
        // 1. Authenticate Token Context Safely
        const authHeader = req.headers.authorization || req.headers.Authorization || "";
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ success: false, error: "Authorization credentials missing." });
        }
        const token = authHeader.split(" ")[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (jwtErr) {
            return res.status(401).json({ success: false, error: "Session token signature expired." });
        }

        // 2. Extract Architectural Headers 
        const actionContext = req.headers["x-action"] || "avatar"; // "avatar" or "chat" or "delete"
        const isAdmin = decodedToken.adminId ? true : false;

        // Target User Selection
        const targetUserUuid = req.headers["x-user-uuid"] || decodedToken.uuid || decodedToken.id;

        if (!targetUserUuid) {
            return res.status(400).json({ success: false, error: "Missing destination target user identification tracking index." });
        }

        // 3. Perform Optional Database Account Pre-checks (ONLY for profile changes)
        let dbUserRecord = null;
        if (actionContext === "avatar" || actionContext === "delete") {
            const { data, error } = await supabase
                .from("users")
                .select("id, uuid, image")
                .eq("uuid", targetUserUuid)
                .maybeSingle();

            if (error || !data) {
                return res.status(444).json({ success: false, error: "Target account validation reference failure." });
            }
            dbUserRecord = data;
        }

        // -------------------------------------------------------------------------
        // PATHWAY 1: ACTION DELETION ROUTE (Profile Picture Only)
        // -------------------------------------------------------------------------
        if (actionContext === "delete") {
            if (dbUserRecord && dbUserRecord.image) {
                try {
                    const oldUrlParts = dbUserRecord.image.split("/storage/v1/object/public/profileimages/");
                    if (oldUrlParts.length === 2) {
                        await supabase.storage.from("profileimages").remove([oldUrlParts[1]]);
                    }
                } catch (err) {
                    console.warn("⚠️ Deletion cleanup skipped:", err.message);
                }
            }

            await supabase.from("users").update({ image: null }).eq("id", dbUserRecord.id);
            return res.status(200).json({ success: true, message: "Profile photo asset removed cleanly." });
        }

        // Enforce write mutation restriction rules exclusively for incoming multi-part file uploads
        if (req.method !== "POST" && req.method !== "PUT") {
            return res.status(405).json({ success: false, error: "Method implementation blocked." });
        }

        // -------------------------------------------------------------------------
        // PATHWAY 2: NATIVE ZERO-DEPENDENCY FILE STREAM CONSUMPTION
        // -------------------------------------------------------------------------
        const chunks = [];
        let contentTypeHeader = req.headers["content-type"] || "";

        let boundaryString = "";
        const match = contentTypeHeader.match(/boundary=(.+)/);
        if (match) {
            boundaryString = match[1];
        }

        const rawFileBuffer = await new Promise((resolve, reject) => {
            req.on("data", (chunk) => chunks.push(chunk));
            req.on("end", () => resolve(Buffer.concat(chunks)));
            req.on("error", (err) => reject(err));
        });

        if (!rawFileBuffer || rawFileBuffer.length === 0) {
            return res.status(400).json({ success: false, error: "No asset stream bytes received." });
        }

        let finalImageBuffer = rawFileBuffer;
        let detectedMimeType = "image/png";
        let extension = "png";

        if (boundaryString) {
            const boundaryBuffer = Buffer.from(`--${boundaryString}`);
            const firstBoundaryIndex = rawFileBuffer.indexOf(boundaryBuffer);

            if (firstBoundaryIndex !== -1) {
                const headerEndIndex = rawFileBuffer.indexOf(Buffer.from("\r\n\r\n"), firstBoundaryIndex);
                if (headerEndIndex !== -1) {
                    const headerText = rawFileBuffer.slice(firstBoundaryIndex, headerEndIndex).toString("binary");

                    const mimeMatch = headerText.match(/Content-Type:\s*([^\s\r\n]+)/i);
                    if (mimeMatch) {
                        detectedMimeType = mimeMatch[1];
                        extension = detectedMimeType.split("/")[1] || "png";
                        if (extension.includes(";")) extension = extension.split(";")[0];
                    }

                    const nextBoundaryIndex = rawFileBuffer.indexOf(boundaryBuffer, headerEndIndex);
                    if (nextBoundaryIndex !== -1) {
                        finalImageBuffer = rawFileBuffer.slice(headerEndIndex + 4, nextBoundaryIndex - 2);
                    } else {
                        // Safe extraction offset fallback rule lines
                        finalImageBuffer = rawFileBuffer.slice(headerEndIndex + 4, rawFileBuffer.length - 2);
                    }
                }
            }
        }

        // 4. Compute Storage Paths dynamically based on exact Action Context
        let targetStorageDestinationPath = "";
        if (actionContext === "chat") {
            targetStorageDestinationPath = `chat_rooms/room_${targetUserUuid}/asset_${Date.now()}.${extension}`;
        } else {
            // Profile Avatars Directory Path Tracking
            targetStorageDestinationPath = `user_profiles/avatar_${targetUserUuid}_${Date.now()}.${extension}`;

            // Clean up previous profile image asset file if replacing an avatar profile picture
            if (dbUserRecord && dbUserRecord.image) {
                try {
                    const oldUrlParts = dbUserRecord.image.split("/storage/v1/object/public/profileimages/");
                    if (oldUrlParts.length === 2) {
                        await supabase.storage.from("profileimages").remove([oldUrlParts[1]]);
                    }
                } catch (err) {
                    console.warn("⚠️ Previous asset replacement cleanup skipped:", err.message);
                }
            }
        }

        // 5. Send Binary Buffer Streams directly into Supabase Storage Buckets
        const { error: storageUploadError } = await supabase.storage
            .from("profileimages")
            .upload(targetStorageDestinationPath, finalImageBuffer, {
                contentType: detectedMimeType,
                upsert: true
            });

        if (storageUploadError) throw new Error(`Cloud Storage core rejection: ${storageUploadError.message}`);

        const { data: publicUrlData } = supabase.storage
            .from("profileimages")
            .getPublicUrl(targetStorageDestinationPath);

        const computedAssetPublicWebUrl = publicUrlData.publicUrl;

        // 6. SQL Database Synchronization Conditional Step (ONLY for profile avatars)
        if (actionContext === "avatar" && dbUserRecord) {
            const { error: dataTableUpdateError } = await supabase
                .from("users")
                .update({ image: computedAssetPublicWebUrl })
                .eq("id", dbUserRecord.id);

            if (dataTableUpdateError) throw new Error(`Database table sync failure: ${dataTableUpdateError.message}`);
        }

        // Return URL link seamlessly for rendering inside chat streams
        return res.status(200).json({
            success: true,
            message: "Asset processing uploaded completed cleanly.",
            imageUrl: computedAssetPublicWebUrl
        });

    } catch (globalFaultException) {
        console.error("❌ Native Stream Avatar Handler Crash:", globalFaultException.message);
        return res.status(500).json({ success: false, error: globalFaultException.message });
    }
}