import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";
import multer from "multer";
import ws from "ws";

const SUPABASE_URL = process.env.PUBLIC_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    realtime: { transport: ws }
});

const processingStorageDriver = multer.memoryStorage();
const multerUploaderInstance = multer({
    storage: processingStorageDriver,
    limits: { fileSize: 4 * 1024 * 1024 }
});

export const config = {
    api: { bodyParser: false }
};

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

    // -------------------------------------------------------------------------
    // METHOD: GET -> Pull Profile Parameters Matrix Data Configuration Rows
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith("Bearer ")) {
                return res.status(401).json({ success: false, error: "Authorization headers missing." });
            }

            const token = authHeader.split(" ")[1];
            let decodedToken;
            try {
                decodedToken = jwt.verify(token, JWT_SECRET);
            } catch (jwtErr) {
                return res.status(401).json({ success: false, error: "Active session expired." });
            }

            const { data: userData, error: userError } = await supabase
                .from("users")
                .select(`
                    id, 
                    uuid, 
                    firstname, 
                    middlename,
                    lastname, 
                    email, 
                    phone, 
                    city, 
                    country, 
                    address, 
                    kinname, 
                    currency, 
                    accttype, 
                    accountBalance, 
                    accountNumber, 
                    activeuser, 
                    block_transection, 
                    image
                `)
                .eq("uuid", decodedToken.uuid)
                .maybeSingle();

            if (userError || !userData) {
                return res.status(444).json({ success: false, error: "User records validation fault." });
            }

            // Clean string checks for structural name interpolation
            const firstName = userData.firstname || "";
            const middleName = userData.middlename ? userData.middlename.trim() : "";
            const lastName = userData.lastname || "";

            const derivedFullName = middleName
                ? `${firstName} ${middleName} ${lastName}`
                : `${firstName} ${lastName}`;

            return res.status(200).json({
                success: true,
                data: {
                    uuid: userData.uuid,
                    fullName: derivedFullName.trim(),
                    email: userData.email,
                    phone: userData.phone,
                    city: userData.city,
                    country: userData.country,
                    address: userData.address,
                    kinname: userData.kinname,
                    currency: userData.currency,
                    accountType: userData.accttype,
                    accountNumber: userData.accountNumber,
                    balance: userData.accountBalance,
                    activeuser: userData.activeuser,
                    block_transection: userData.block_transection,
                    image: userData.image
                }
            });

        } catch (fetchException) {
            console.error("❌ GET Backend Profile Crash Log:", fetchException.message);
            return res.status(500).json({ success: false, error: fetchException.message });
        }
    }

    // -------------------------------------------------------------------------
    // METHOD: POST -> Handle Profile Avatar Image Upload Configuration
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
        return multerUploaderInstance.single("avatarImageFile")(req, res, async (multerProcessingError) => {
            if (multerProcessingError) {
                return res.status(400).json({ success: false, error: `Multer Error: ${multerProcessingError.message}` });
            }

            try {
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith("Bearer ")) {
                    return res.status(401).json({ success: false, error: "Authorization token pointers missing." });
                }

                const token = authHeader.split(" ")[1];
                let decodedToken = jwt.verify(token, JWT_SECRET);

                const { data: userData, error: userError } = await supabase
                    .from("users")
                    .select("id, uuid")
                    .eq("uuid", decodedToken.uuid)
                    .maybeSingle();

                if (userError || !userData) {
                    return res.status(444).json({ success: false, error: "Identity tracking validation exception." });
                }

                if (!req.file) {
                    return res.status(400).json({ success: false, error: "No binary upload asset streams detected." });
                }

                const binaryFileBuffer = req.file.buffer;
                const fileExtensionString = req.file.originalname.split('.').pop() || "png";
                const targetStorageDestinationPath = `user_profiles/avatar_${userData.uuid}_${Date.now()}.${fileExtensionString}`;

                const { error: storageUploadError } = await supabase.storage
                    .from("profileimages")
                    .upload(targetStorageDestinationPath, binaryFileBuffer, {
                        contentType: req.file.mimetype,
                        upsert: true
                    });

                if (storageUploadError) throw new Error(`Cloud Storage core rejection: ${storageUploadError.message}`);

                const { data: publicUrlData } = supabase.storage
                    .from("profileimages")
                    .getPublicUrl(targetStorageDestinationPath);

                const computedAssetPublicWebUrl = publicUrlData.publicUrl;

                const { error: dataTableUpdateError } = await supabase
                    .from("users")
                    .update({ image: computedAssetPublicWebUrl })
                    .eq("id", userData.id);

                if (dataTableUpdateError) throw new Error(`Database record synchronization failure: ${dataTableUpdateError.message}`);

                return res.status(200).json({
                    success: true,
                    message: "Profile image sync complete.",
                    imageUrl: computedAssetPublicWebUrl
                });

            } catch (globalFaultException) {
                console.error("❌ POST Backend Avatar Crash Log:", globalFaultException.message);
                return res.status(500).json({ success: false, error: globalFaultException.message });
            }
        });
    }

    // Catch-all for any other methods (PUT, DELETE, etc.)
    return res.status(405).json({ success: false, error: "HTTP Method type not permitted." });
}