require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const STORAGE_BUCKET = process.env.STORAGE_BUCKET || "user-files";
const MAX_FILE_SIZE_MB = Number(process.env.MAX_FILE_SIZE_MB || 100);

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing required Supabase environment variables.");
  process.exit(1);
}

const supabaseAdmin = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

const supabasePublic = createClient(
  SUPABASE_URL,
  SUPABASE_ANON_KEY
);

/* -------------------------------------------------------
   BASIC APP SETTINGS
------------------------------------------------------- */

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin"
    },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "https://cdn.jsdelivr.net",
          "https://*.supabase.co"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'"
        ],
        imgSrc: [
          "'self'",
          "data:",
          "blob:",
          "https://*.supabase.co"
        ],
        connectSrc: [
          "'self'",
          SUPABASE_URL,
          "https://*.supabase.co"
        ],
        fontSrc: [
          "'self'",
          "data:"
        ],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

/* -------------------------------------------------------
   RATE LIMITING
------------------------------------------------------- */

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts. Please try again later."
  }
});

app.use("/api/", generalLimiter);

/* -------------------------------------------------------
   HELPERS
------------------------------------------------------- */

function cleanString(value, maxLength = 500) {
  if (value === undefined || value === null) return "";
  return String(value).trim().slice(0, maxLength);
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || "")
  );
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function safeFileName(name) {
  return cleanString(name, 255)
    .replace(/[\/\\]/g, "_")
    .replace(/\0/g, "")
    .replace(/\.\./g, "_");
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim() || null;
}

async function getUserFromRequest(req) {
  const token = getBearerToken(req);

  if (!token) {
    return {
      user: null,
      error: "Missing authentication token."
    };
  }

  const {
    data: { user },
    error
  } = await supabaseAdmin.auth.getUser(token);

  if (error || !user) {
    return {
      user: null,
      error: "Invalid or expired authentication token."
    };
  }

  return {
    user,
    error: null
  };
}

async function requireAuth(req, res, next) {
  const result = await getUserFromRequest(req);

  if (!result.user) {
    return res.status(401).json({
      error: result.error || "Authentication required."
    });
  }

  req.user = result.user;
  next();
}

async function getProfile(userId) {
  const { data, error } = await supabaseAdmin
    .from("profiles")
    .select("*")
    .eq("id", userId)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}

async function requireAdmin(req, res, next) {
  try {
    const profile = await getProfile(req.user.id);

    if (!profile || profile.role !== "admin") {
      return res.status(403).json({
        error: "Administrator access required."
      });
    }

    req.profile = profile;
    next();
  } catch (error) {
    console.error("Admin check error:", error);

    return res.status(500).json({
      error: "Unable to verify administrator access."
    });
  }
}

async function logActivity(userId, action, details = {}) {
  try {
    await supabaseAdmin
      .from("activity_logs")
      .insert({
        user_id: userId,
        action,
        details
      });
  } catch (error) {
    console.error("Activity log error:", error.message);
  }
}

async function getFileForUser(fileId, userId) {
  if (!validUUID(fileId)) {
    return {
      file: null,
      error: "Invalid file ID."
    };
  }

  const { data, error } = await supabaseAdmin
    .from("files")
    .select("*")
    .eq("id", fileId)
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    return {
      file: null,
      error: error.message
    };
  }

  if (!data) {
    return {
      file: null,
      error: "File not found."
    };
  }

  return {
    file: data,
    error: null
  };
}

function publicFileData(file) {
  if (!file) return null;

  return {
    id: file.id,
    name: file.name,
    mime_type: file.mime_type,
    size_bytes: file.size_bytes,
    description: file.description,
    client_id: file.client_id,
    is_deleted: file.is_deleted,
    deleted_at: file.deleted_at,
    created_at: file.created_at,
    updated_at: file.updated_at
  };
}

/* -------------------------------------------------------
   HEALTH
------------------------------------------------------- */

app.get("/api/health", async (req, res) => {
  res.json({
    ok: true,
    service: "data-security",
    timestamp: new Date().toISOString()
  });
});

/* -------------------------------------------------------
   PUBLIC CONFIG
   NEVER SEND SERVICE ROLE KEY
------------------------------------------------------- */

app.get("/api/config", (req, res) => {
  res.json({
    supabaseUrl: SUPABASE_URL,
    supabaseAnonKey: SUPABASE_ANON_KEY,
    storageBucket: STORAGE_BUCKET,
    maxFileSizeMB: MAX_FILE_SIZE_MB
  });
});

/* -------------------------------------------------------
   LOGIN IDENTITY
   Allows username OR email login.
------------------------------------------------------- */

app.post("/api/login-identity", authLimiter, async (req, res) => {
  try {
    const identity = cleanString(req.body.identity, 320);

    if (!identity) {
      return res.status(400).json({
        error: "Email or username is required."
      });
    }

    if (identity.includes("@")) {
      return res.json({
        email: identity.toLowerCase()
      });
    }

    const { data: profile, error } = await supabaseAdmin
      .from("profiles")
      .select("email")
      .ilike("username", identity)
      .maybeSingle();

    if (error) {
      console.error("Identity lookup error:", error);

      return res.status(500).json({
        error: "Unable to find account."
      });
    }

    if (!profile) {
      return res.status(404).json({
        error: "Account not found."
      });
    }

    return res.json({
      email: profile.email
    });
  } catch (error) {
    console.error("Login identity error:", error);

    res.status(500).json({
      error: "Unable to process login."
    });
  }
});

/* -------------------------------------------------------
   REGISTER
------------------------------------------------------- */

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const username = cleanString(req.body.username, 50);
    const email = cleanString(req.body.email, 320).toLowerCase();
    const password = String(req.body.password || "");
    const referral = cleanString(req.body.referral, 100);

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "Username, email and password are required."
      });
    }

    if (!/^[a-zA-Z0-9_.-]{3,50}$/.test(username)) {
      return res.status(400).json({
        error:
          "Username must be 3-50 characters and contain only letters, numbers, dot, dash or underscore."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters."
      });
    }

    const expectedReferral = process.env.REFERRAL_CODE;

    if (expectedReferral && referral !== expectedReferral) {
      return res.status(400).json({
        error: "Invalid referral code."
      });
    }

    const { data: existingUsername, error: usernameError } =
      await supabaseAdmin
        .from("profiles")
        .select("id")
        .ilike("username", username)
        .maybeSingle();

    if (usernameError) {
      console.error("Username check error:", usernameError);

      return res.status(500).json({
        error: "Unable to validate username."
      });
    }

    if (existingUsername) {
      return res.status(409).json({
        error: "Username is already taken."
      });
    }

    const { data: authData, error: authError } =
      await supabaseAdmin.auth.admin.createUser({
        email,
        password,
        email_confirm: true
      });

    if (authError) {
      const message = authError.message || "Unable to create account.";

      if (
        message.toLowerCase().includes("already") ||
        message.toLowerCase().includes("registered")
      ) {
        return res.status(409).json({
          error: "An account with this email already exists."
        });
      }

      return res.status(400).json({
        error: message
      });
    }

    const user = authData.user;

    const { error: profileError } = await supabaseAdmin
      .from("profiles")
      .insert({
        id: user.id,
        username,
        email,
        role: "user"
      });

    if (profileError) {
      console.error("Profile creation error:", profileError);

      await supabaseAdmin.auth.admin.deleteUser(user.id);

      return res.status(500).json({
        error: "Unable to create user profile."
      });
    }

    await logActivity(user.id, "account_created", {
      username,
      referralUsed: Boolean(referral)
    });

    return res.status(201).json({
      success: true,
      message: "Account created successfully."
    });
  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

/* -------------------------------------------------------
   CURRENT USER
------------------------------------------------------- */

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    let profile = await getProfile(req.user.id);

    if (!profile) {
      const { data, error } = await supabaseAdmin
        .from("profiles")
        .insert({
          id: req.user.id,
          email: req.user.email,
          username: req.user.email?.split("@")[0] || "user",
          role: "user"
        })
        .select("*")
        .single();

      if (error) {
        throw error;
      }

      profile = data;
    }

    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        created_at: req.user.created_at
      },
      profile
    });
  } catch (error) {
    console.error("Me error:", error);

    res.status(500).json({
      error: "Unable to load account."
    });
  }
});

/* -------------------------------------------------------
   FILES - LIST
------------------------------------------------------- */

app.get("/api/files", requireAuth, async (req, res) => {
  try {
    const includeDeleted = req.query.deleted === "true";

    let query = supabaseAdmin
      .from("files")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", {
        ascending: false
      });

    if (!includeDeleted) {
      query = query.eq("is_deleted", false);
    } else {
      query = query.eq("is_deleted", true);
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    res.json({
      files: data || []
    });
  } catch (error) {
    console.error("Files list error:", error);

    res.status(500).json({
      error: "Unable to load files."
    });
  }
});

/* -------------------------------------------------------
   FILE REGISTER
   Browser uploads directly to Supabase Storage.
------------------------------------------------------- */

app.post("/api/files/register", requireAuth, async (req, res) => {
  try {
    const name = safeFileName(req.body.name);
    const storagePath = cleanString(req.body.storagePath, 1000);
    const mimeType = cleanString(req.body.mimeType, 255);
    const sizeBytes = Number(req.body.sizeBytes || 0);
    const description = cleanString(req.body.description, 2000);
    const clientId = cleanString(req.body.clientId, 100);

    if (!name || !storagePath) {
      return res.status(400).json({
        error: "File information is incomplete."
      });
    }

    if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) {
      return res.status(400).json({
        error: "Invalid file size."
      });
    }

    const maxBytes = MAX_FILE_SIZE_MB * 1024 * 1024;

    if (sizeBytes > maxBytes) {
      return res.status(400).json({
        error: `File exceeds the ${MAX_FILE_SIZE_MB} MB limit.`
      });
    }

    const expectedPrefix = `${req.user.id}/`;

    if (!storagePath.startsWith(expectedPrefix)) {
      return res.status(403).json({
        error: "Invalid storage path."
      });
    }

    if (clientId && !validUUID(clientId)) {
      return res.status(400).json({
        error: "Invalid client."
      });
    }

    if (clientId) {
      const { data: client } = await supabaseAdmin
        .from("clients")
        .select("id")
        .eq("id", clientId)
        .eq("user_id", req.user.id)
        .maybeSingle();

      if (!client) {
        return res.status(400).json({
          error: "Selected client does not belong to this account."
        });
      }
    }

    const { data, error } = await supabaseAdmin
      .from("files")
      .insert({
        user_id: req.user.id,
        client_id: clientId || null,
        name,
        storage_path: storagePath,
        mime_type: mimeType || "application/octet-stream",
        size_bytes: sizeBytes,
        description,
        is_deleted: false
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "file_uploaded", {
      fileId: data.id,
      fileName: data.name,
      sizeBytes: data.size_bytes
    });

    res.status(201).json({
      success: true,
      file: data
    });
  } catch (error) {
    console.error("File register error:", error);

    res.status(500).json({
      error: "Unable to save uploaded file."
    });
  }
});

/* -------------------------------------------------------
   DOWNLOAD
------------------------------------------------------- */

app.get("/api/files/:id/download", requireAuth, async (req, res) => {
  try {
    const result = await getFileForUser(
      req.params.id,
      req.user.id
    );

    if (!result.file) {
      return res.status(404).json({
        error: result.error || "File not found."
      });
    }

    const file = result.file;

    if (file.is_deleted) {
      return res.status(404).json({
        error: "File is in trash."
      });
    }

    const { data, error } = await supabaseAdmin.storage
      .from(STORAGE_BUCKET)
      .createSignedUrl(file.storage_path, 60);

    if (error || !data?.signedUrl) {
      console.error("Signed URL error:", error);

      return res.status(500).json({
        error: "Unable to create download link."
      });
    }

    await logActivity(req.user.id, "file_downloaded", {
      fileId: file.id,
      fileName: file.name
    });

    res.json({
      url: data.signedUrl,
      name: file.name
    });
  } catch (error) {
    console.error("Download error:", error);

    res.status(500).json({
      error: "Unable to download file."
    });
  }
});

/* -------------------------------------------------------
   TRASH
------------------------------------------------------- */

app.post("/api/files/:id/trash", requireAuth, async (req, res) => {
  try {
    const result = await getFileForUser(
      req.params.id,
      req.user.id
    );

    if (!result.file) {
      return res.status(404).json({
        error: result.error || "File not found."
      });
    }

    const { data, error } = await supabaseAdmin
      .from("files")
      .update({
        is_deleted: true,
        deleted_at: new Date().toISOString()
      })
      .eq("id", result.file.id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "file_trashed", {
      fileId: data.id,
      fileName: data.name
    });

    res.json({
      success: true,
      file: data
    });
  } catch (error) {
    console.error("Trash error:", error);

    res.status(500).json({
      error: "Unable to move file to trash."
    });
  }
});

/* -------------------------------------------------------
   RESTORE
------------------------------------------------------- */

app.post("/api/files/:id/restore", requireAuth, async (req, res) => {
  try {
    const result = await getFileForUser(
      req.params.id,
      req.user.id
    );

    if (!result.file) {
      return res.status(404).json({
        error: result.error || "File not found."
      });
    }

    const { data, error } = await supabaseAdmin
      .from("files")
      .update({
        is_deleted: false,
        deleted_at: null
      })
      .eq("id", result.file.id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "file_restored", {
      fileId: data.id,
      fileName: data.name
    });

    res.json({
      success: true,
      file: data
    });
  } catch (error) {
    console.error("Restore error:", error);

    res.status(500).json({
      error: "Unable to restore file."
    });
  }
});

/* -------------------------------------------------------
   PERMANENT DELETE
------------------------------------------------------- */

app.delete("/api/files/:id", requireAuth, async (req, res) => {
  try {
    const result = await getFileForUser(
      req.params.id,
      req.user.id
    );

    if (!result.file) {
      return res.status(404).json({
        error: result.error || "File not found."
      });
    }

    const file = result.file;

    const { error: storageError } = await supabaseAdmin.storage
      .from(STORAGE_BUCKET)
      .remove([file.storage_path]);

    if (storageError) {
      console.error("Storage delete error:", storageError);
    }

    const { error: dbError } = await supabaseAdmin
      .from("files")
      .delete()
      .eq("id", file.id)
      .eq("user_id", req.user.id);

    if (dbError) {
      throw dbError;
    }

    await supabaseAdmin
      .from("share_links")
      .delete()
      .eq("file_id", file.id);

    await logActivity(req.user.id, "file_deleted", {
      fileId: file.id,
      fileName: file.name
    });

    res.json({
      success: true
    });
  } catch (error) {
    console.error("Permanent delete error:", error);

    res.status(500).json({
      error: "Unable to permanently delete file."
    });
  }
});

/* -------------------------------------------------------
   CLIENTS
------------------------------------------------------- */

app.get("/api/clients", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("clients")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", {
        ascending: false
      });

    if (error) {
      throw error;
    }

    res.json({
      clients: data || []
    });
  } catch (error) {
    console.error("Clients error:", error);

    res.status(500).json({
      error: "Unable to load clients."
    });
  }
});

app.post("/api/clients", requireAuth, async (req, res) => {
  try {
    const name = cleanString(req.body.name, 150);
    const email = cleanString(req.body.email, 320);
    const phone = cleanString(req.body.phone, 80);
    const notes = cleanString(req.body.notes, 2000);

    if (!name) {
      return res.status(400).json({
        error: "Client name is required."
      });
    }

    const { data, error } = await supabaseAdmin
      .from("clients")
      .insert({
        user_id: req.user.id,
        name,
        email,
        phone,
        notes
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "client_created", {
      clientId: data.id,
      clientName: data.name
    });

    res.status(201).json({
      success: true,
      client: data
    });
  } catch (error) {
    console.error("Client create error:", error);

    res.status(500).json({
      error: "Unable to create client."
    });
  }
});

app.put("/api/clients/:id", requireAuth, async (req, res) => {
  try {
    if (!validUUID(req.params.id)) {
      return res.status(400).json({
        error: "Invalid client ID."
      });
    }

    const updates = {
      name: cleanString(req.body.name, 150),
      email: cleanString(req.body.email, 320),
      phone: cleanString(req.body.phone, 80),
      notes: cleanString(req.body.notes, 2000)
    };

    if (!updates.name) {
      return res.status(400).json({
        error: "Client name is required."
      });
    }

    const { data, error } = await supabaseAdmin
      .from("clients")
      .update(updates)
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "client_updated", {
      clientId: data.id,
      clientName: data.name
    });

    res.json({
      success: true,
      client: data
    });
  } catch (error) {
    console.error("Client update error:", error);

    res.status(500).json({
      error: "Unable to update client."
    });
  }
});

app.delete("/api/clients/:id", requireAuth, async (req, res) => {
  try {
    if (!validUUID(req.params.id)) {
      return res.status(400).json({
        error: "Invalid client ID."
      });
    }

    const { data: client } = await supabaseAdmin
      .from("clients")
      .select("id,name")
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (!client) {
      return res.status(404).json({
        error: "Client not found."
      });
    }

    const { error } = await supabaseAdmin
      .from("clients")
      .delete()
      .eq("id", client.id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "client_deleted", {
      clientId: client.id,
      clientName: client.name
    });

    res.json({
      success: true
    });
  } catch (error) {
    console.error("Client delete error:", error);

    res.status(500).json({
      error: "Unable to delete client."
    });
  }
});

/* -------------------------------------------------------
   SHARES
------------------------------------------------------- */

app.get("/api/shares", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("share_links")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", {
        ascending: false
      });

    if (error) {
      throw error;
    }

    const shares = data || [];

    const fileIds = [
      ...new Set(
        shares
          .map((share) => share.file_id)
          .filter(Boolean)
      )
    ];

    let files = [];

    if (fileIds.length) {
      const result = await supabaseAdmin
        .from("files")
        .select("id,name")
        .in("id", fileIds)
        .eq("user_id", req.user.id);

      files = result.data || [];
    }

    const fileMap = new Map(
      files.map((file) => [file.id, file])
    );

    res.json({
      shares: shares.map((share) => ({
        ...share,
        file: fileMap.get(share.file_id) || null
      }))
    });
  } catch (error) {
    console.error("Shares list error:", error);

    res.status(500).json({
      error: "Unable to load share links."
    });
  }
});

app.post("/api/shares", requireAuth, async (req, res) => {
  try {
    const fileId = cleanString(req.body.fileId, 100);
    const expiration = cleanString(req.body.expiresAt, 100);

    if (!validUUID(fileId)) {
      return res.status(400).json({
        error: "Invalid file."
      });
    }

    const { file, error: fileError } = await getFileForUser(
      fileId,
      req.user.id
    );

    if (!file) {
      return res.status(404).json({
        error: fileError || "File not found."
      });
    }

    if (file.is_deleted) {
      return res.status(400).json({
        error: "Files in trash cannot be shared."
      });
    }

    let expiresAt = null;

    if (expiration) {
      const parsed = new Date(expiration);

      if (Number.isNaN(parsed.getTime())) {
        return res.status(400).json({
          error: "Invalid expiration date."
        });
      }

      if (parsed.getTime() <= Date.now()) {
        return res.status(400).json({
          error: "Expiration must be in the future."
        });
      }

      expiresAt = parsed.toISOString();
    }

    const token = generateToken();

    const { data, error } = await supabaseAdmin
      .from("share_links")
      .insert({
        file_id: file.id,
        user_id: req.user.id,
        token,
        expires_at: expiresAt
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "share_created", {
      shareId: data.id,
      fileId: file.id,
      fileName: file.name
    });

    res.status(201).json({
      success: true,
      share: data,
      url: `/share/${token}`
    });
  } catch (error) {
    console.error("Share create error:", error);

    res.status(500).json({
      error: "Unable to create share link."
    });
  }
});

app.delete("/api/shares/:id", requireAuth, async (req, res) => {
  try {
    if (!validUUID(req.params.id)) {
      return res.status(400).json({
        error: "Invalid share ID."
      });
    }

    const { data: share } = await supabaseAdmin
      .from("share_links")
      .select("*")
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (!share) {
      return res.status(404).json({
        error: "Share link not found."
      });
    }

    const { error } = await supabaseAdmin
      .from("share_links")
      .update({
        revoked_at: new Date().toISOString()
      })
      .eq("id", share.id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "share_revoked", {
      shareId: share.id,
      fileId: share.file_id
    });

    res.json({
      success: true
    });
  } catch (error) {
    console.error("Share revoke error:", error);

    res.status(500).json({
      error: "Unable to revoke share link."
    });
  }
});

/* -------------------------------------------------------
   PUBLIC SHARE
------------------------------------------------------- */

app.get("/api/public-share/:token", async (req, res) => {
  try {
    const token = cleanString(req.params.token, 100);

    if (!token || token.length < 20) {
      return res.status(404).json({
        error: "Share link not found."
      });
    }

    const { data: share, error: shareError } =
      await supabaseAdmin
        .from("share_links")
        .select("*")
        .eq("token", token)
        .maybeSingle();

    if (shareError) {
      throw shareError;
    }

    if (!share) {
      return res.status(404).json({
        error: "Share link not found."
      });
    }

    if (share.revoked_at) {
      return res.status(410).json({
        error: "This share link has been revoked."
      });
    }

    if (
      share.expires_at &&
      new Date(share.expires_at).getTime() <= Date.now()
    ) {
      return res.status(410).json({
        error: "This share link has expired."
      });
    }

    const { data: file, error: fileError } =
      await supabaseAdmin
        .from("files")
        .select("*")
        .eq("id", share.file_id)
        .maybeSingle();

    if (fileError) {
      throw fileError;
    }

    if (!file || file.is_deleted) {
      return res.status(404).json({
        error: "Shared file is no longer available."
      });
    }

    const { data: signed, error: signedError } =
      await supabaseAdmin.storage
        .from(STORAGE_BUCKET)
        .createSignedUrl(file.storage_path, 300);

    if (signedError || !signed?.signedUrl) {
      throw signedError || new Error("Unable to create file URL.");
    }

    res.json({
      success: true,
      file: publicFileData(file),
      downloadUrl: signed.signedUrl,
      expiresAt: share.expires_at
    });
  } catch (error) {
    console.error("Public share error:", error);

    res.status(500).json({
      error: "Unable to open shared file."
    });
  }
});

/* -------------------------------------------------------
   ACTIVITY
------------------------------------------------------- */

app.get("/api/activity", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(
      Math.max(Number(req.query.limit || 100), 1),
      200
    );

    const { data, error } = await supabaseAdmin
      .from("activity_logs")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", {
        ascending: false
      })
      .limit(limit);

    if (error) {
      throw error;
    }

    res.json({
      activity: data || []
    });
  } catch (error) {
    console.error("Activity error:", error);

    res.status(500).json({
      error: "Unable to load activity."
    });
  }
});

/* -------------------------------------------------------
   PROFILE / SETTINGS
------------------------------------------------------- */

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const username = cleanString(req.body.username, 50);
    const avatarUrl = cleanString(req.body.avatarUrl, 1000);

    if (!username) {
      return res.status(400).json({
        error: "Username is required."
      });
    }

    if (!/^[a-zA-Z0-9_.-]{3,50}$/.test(username)) {
      return res.status(400).json({
        error: "Invalid username."
      });
    }

    const { data: existing } = await supabaseAdmin
      .from("profiles")
      .select("id")
      .ilike("username", username)
      .neq("id", req.user.id)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        error: "Username is already taken."
      });
    }

    const { data, error } = await supabaseAdmin
      .from("profiles")
      .update({
        username,
        avatar_url: avatarUrl || null
      })
      .eq("id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await logActivity(req.user.id, "profile_updated", {
      username
    });

    res.json({
      success: true,
      profile: data
    });
  } catch (error) {
    console.error("Profile update error:", error);

    res.status(500).json({
      error: "Unable to update profile."
    });
  }
});

/* -------------------------------------------------------
   ADMIN STATS
------------------------------------------------------- */

app.get(
  "/api/admin/stats",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const [
        usersResult,
        filesResult,
        sharesResult
      ] = await Promise.all([
        supabaseAdmin
          .from("profiles")
          .select("id", {
            count: "exact",
            head: true
          }),

        supabaseAdmin
          .from("files")
          .select("id,size_bytes", {
            count: "exact"
          })
          .eq("is_deleted", false),

        supabaseAdmin
          .from("share_links")
          .select("id", {
            count: "exact",
            head: true
          })
          .is("revoked_at", null)
      ]);

      if (usersResult.error) throw usersResult.error;
      if (filesResult.error) throw filesResult.error;
      if (sharesResult.error) throw sharesResult.error;

      const files = filesResult.data || [];

      const totalStorage = files.reduce(
        (sum, file) =>
          sum + Number(file.size_bytes || 0),
        0
      );

      res.json({
        users: usersResult.count || 0,
        files: filesResult.count || 0,
        storage: totalStorage,
        shares: sharesResult.count || 0
      });
    } catch (error) {
      console.error("Admin stats error:", error);

      res.status(500).json({
        error: "Unable to load administrator statistics."
      });
    }
  }
);

/* -------------------------------------------------------
   ADMIN USERS
------------------------------------------------------- */

app.get(
  "/api/admin/users",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabaseAdmin
        .from("profiles")
        .select("*")
        .order("created_at", {
          ascending: false
        });

      if (error) {
        throw error;
      }

      res.json({
        users: data || []
      });
    } catch (error) {
      console.error("Admin users error:", error);

      res.status(500).json({
        error: "Unable to load users."
      });
    }
  }
);

/* -------------------------------------------------------
   ADMIN FILES
------------------------------------------------------- */

app.get(
  "/api/admin/files",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabaseAdmin
        .from("files")
        .select("*")
        .order("created_at", {
          ascending: false
        })
        .limit(500);

      if (error) {
        throw error;
      }

      res.json({
        files: data || []
      });
    } catch (error) {
      console.error("Admin files error:", error);

      res.status(500).json({
        error: "Unable to load files."
      });
    }
  }
);

/* -------------------------------------------------------
   ADMIN SHARES
------------------------------------------------------- */

app.get(
  "/api/admin/shares",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabaseAdmin
        .from("share_links")
        .select("*")
        .order("created_at", {
          ascending: false
        })
        .limit(500);

      if (error) {
        throw error;
      }

      res.json({
        shares: data || []
      });
    } catch (error) {
      console.error("Admin shares error:", error);

      res.status(500).json({
        error: "Unable to load share links."
      });
    }
  }
);

/* -------------------------------------------------------
   OPTIONAL ADMIN BOOTSTRAP
   Creates the configured admin only when it does not exist.
   It NEVER resets an existing admin password.
------------------------------------------------------- */

async function ensureAdminAccount() {
  const email = cleanString(
    process.env.ADMIN_EMAIL,
    320
  ).toLowerCase();

  const password = String(
    process.env.ADMIN_PASSWORD || ""
  );

  if (!email || !password) {
    console.log(
      "ADMIN_EMAIL / ADMIN_PASSWORD not configured. Skipping admin bootstrap."
    );
    return;
  }

  try {
    let targetUser = null;

    const perPage = 1000;
    let page = 1;

    while (!targetUser) {
      const { data, error } =
        await supabaseAdmin.auth.admin.listUsers({
          page,
          perPage
        });

      if (error) {
        throw error;
      }

      const users = data?.users || [];

      targetUser = users.find(
        (u) =>
          String(u.email || "").toLowerCase() === email
      );

      if (
        targetUser ||
        users.length < perPage
      ) {
        break;
      }

      page++;
    }

    if (!targetUser) {
      const { data, error } =
        await supabaseAdmin.auth.admin.createUser({
          email,
          password,
          email_confirm: true
        });

      if (error) {
        throw error;
      }

      targetUser = data.user;

      console.log(
        "Admin account created for configured ADMIN_EMAIL."
      );
    }

    const { error: profileError } =
      await supabaseAdmin
        .from("profiles")
        .upsert(
          {
            id: targetUser.id,
            email,
            username:
              email.split("@")[0] || "admin",
            role: "admin"
          },
          {
            onConflict: "id"
          }
        );

    if (profileError) {
      throw profileError;
    }

    console.log("Admin profile verified.");
  } catch (error) {
    console.error(
      "Admin bootstrap failed:",
      error.message
    );
  }
}

/* -------------------------------------------------------
   STATIC FILES
------------------------------------------------------- */

const publicDir = path.join(
  __dirname,
  "public"
);

app.use(
  express.static(publicDir, {
    index: false,
    maxAge: "1h"
  })
);

/* -------------------------------------------------------
   SPA FALLBACK
   IMPORTANT:
   Do NOT use app.get("*") with Express 5.
------------------------------------------------------- */

app.use((req, res, next) => {
  if (
    req.method !== "GET" ||
    req.path.startsWith("/api/")
  ) {
    return next();
  }

  if (req.path.startsWith("/share/")) {
    return res.sendFile(
      path.join(publicDir, "index.html")
    );
  }

  return res.sendFile(
    path.join(publicDir, "index.html")
  );
});

/* -------------------------------------------------------
   404
------------------------------------------------------- */

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found."
    });
  }

  res.status(404).send("Page not found.");
});

/* -------------------------------------------------------
   ERROR HANDLER
------------------------------------------------------- */

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Internal server error."
  });
});

/* -------------------------------------------------------
   START
------------------------------------------------------- */

app.listen(PORT, async () => {
  console.log(
    `Data Security server running on port ${PORT}`
  );

  await ensureAdminAccount();
});