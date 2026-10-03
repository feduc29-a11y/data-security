const path = require("path");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const REFERRAL_CODE = process.env.REFERRAL_CODE || "404";
const STORAGE_BUCKET = process.env.STORAGE_BUCKET || "user-files";
const MAX_FILE_SIZE_MB = Number(process.env.MAX_FILE_SIZE_MB || 100);

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE_KEY) {
  console.error("Missing required Supabase environment variables.");
}

const adminDb = createClient(SUPABASE_URL || "", SERVICE_ROLE_KEY || "", {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.set("trust proxy", 1);
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 80,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use("/api/register", authLimiter);
app.use("/api/login-identity", authLimiter);

function clientFromToken(token) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { autoRefreshToken: false, persistSession: false }
  });
}

async function requireUser(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Authentication required." });
    }

    const token = header.slice(7);
    const client = clientFromToken(token);
    const { data: { user }, error } = await client.auth.getUser();

    if (error || !user) {
      return res.status(401).json({ error: "Invalid or expired session." });
    }

    const { data: profile, error: profileError } = await adminDb
      .from("profiles")
      .select("id,username,email,role,disabled")
      .eq("id", user.id)
      .maybeSingle();

    if (profileError) {
      return res.status(500).json({ error: profileError.message });
    }

    if (!profile) {
      return res.status(403).json({ error: "Profile not found." });
    }

    if (profile.disabled) {
      return res.status(403).json({ error: "This account is disabled." });
    }

    req.user = user;
    req.profile = profile;
    req.client = client;
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Authentication failed." });
  }
}

async function requireAdmin(req, res, next) {
  await requireUser(req, res, async () => {
    if (req.profile.role !== "admin") {
      return res.status(403).json({ error: "Admin access required." });
    }
    next();
  });
}

function safeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,32}$/.test(username);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function objectPath(userId, fileId, originalName) {
  const clean = String(originalName || "file").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120);
  return `${userId}/${fileId}-${clean}`;
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "Data Security" });
});

app.get("/api/config", (req, res) => {
  res.json({
    supabaseUrl: SUPABASE_URL,
    supabaseAnonKey: SUPABASE_ANON_KEY,
    storageBucket: STORAGE_BUCKET,
    maxFileSizeMb: MAX_FILE_SIZE_MB
  });
});

app.post("/api/check-referral", (req, res) => {
  res.json({ valid: String(req.body.code || "") === REFERRAL_CODE });
});

app.post("/api/login-identity", async (req, res) => {
  try {
    const identity = String(req.body.identity || "").trim().toLowerCase();
    if (!identity) return res.status(400).json({ error: "Username or email is required." });

    if (identity.includes("@")) {
      return res.json({ email: identity });
    }

    const { data, error } = await adminDb
      .from("profiles")
      .select("email,disabled")
      .eq("username", identity)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Account not found." });
    if (data.disabled) return res.status(403).json({ error: "This account is disabled." });

    res.json({ email: data.email });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Unable to resolve account." });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const username = safeUsername(req.body.username);
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");
    const referral = String(req.body.referralCode || "");

    if (referral !== REFERRAL_CODE) {
      return res.status(400).json({ error: "Invalid referral code." });
    }

    if (!isValidUsername(username)) {
      return res.status(400).json({ error: "Username must be 3-32 characters and use only letters, numbers, _, ., or -." });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match." });
    }

    const { data: existingUsername, error: usernameError } = await adminDb
      .from("profiles")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (usernameError) return res.status(500).json({ error: usernameError.message });
    if (existingUsername) return res.status(409).json({ error: "Username is already taken." });

    const { data: created, error: createError } = await adminDb.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username }
    });

    if (createError) return res.status(400).json({ error: createError.message });

    const { error: profileError } = await adminDb
      .from("profiles")
      .insert({
        id: created.user.id,
        username,
        email,
        role: "user",
        disabled: false
      });

    if (profileError) {
      await adminDb.auth.admin.deleteUser(created.user.id);
      return res.status(500).json({ error: "Could not create user profile." });
    }

    await adminDb.from("activity_logs").insert({
      user_id: created.user.id,
      action: "account_registered",
      details: { username }
    });

    res.status(201).json({
      ok: true,
      message: "Account created. You can now sign in."
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.get("/api/me", requireUser, async (req, res) => {
  res.json({ user: req.user, profile: req.profile });
});

app.get("/api/files", requireUser, async (req, res) => {
  const { data, error } = await adminDb
    .from("files")
    .select("*")
    .eq("owner_id", req.user.id)
    .eq("is_trashed", false)
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ files: data || [] });
});

app.get("/api/trash", requireUser, async (req, res) => {
  const { data, error } = await adminDb
    .from("files")
    .select("*")
    .eq("owner_id", req.user.id)
    .eq("is_trashed", true)
    .order("deleted_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ files: data || [] });
});

app.post("/api/files/register", requireUser, async (req, res) => {
  try {
    const {
      id, originalName, description, clientName, category,
      tags, mimeType, size, sha256: digest
    } = req.body;

    if (!id || !originalName) {
      return res.status(400).json({ error: "Missing file information." });
    }

    const bytes = Number(size);
    if (!Number.isFinite(bytes) || bytes < 0 || bytes > MAX_FILE_SIZE_MB * 1024 * 1024) {
      return res.status(400).json({ error: `File exceeds the ${MAX_FILE_SIZE_MB} MB limit.` });
    }

    const filePath = objectPath(req.user.id, id, originalName);

    const { data, error } = await adminDb.from("files").insert({
      id,
      owner_id: req.user.id,
      original_name: originalName,
      storage_path: filePath,
      description: String(description || "").slice(0, 2000),
      client_name: String(clientName || "").slice(0, 120),
      category: String(category || "Other").slice(0, 60),
      tags: Array.isArray(tags) ? tags.slice(0, 20) : [],
      mime_type: String(mimeType || "application/octet-stream").slice(0, 180),
      size: bytes,
      sha256: digest || null
    }).select().single();

    if (error) return res.status(400).json({ error: error.message });

    await adminDb.from("activity_logs").insert({
      user_id: req.user.id,
      action: "file_uploaded",
      details: { file_id: id, name: originalName, size: bytes }
    });

    res.status(201).json({ file: data });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not save file metadata." });
  }
});

app.post("/api/files/:id/signed-url", requireUser, async (req, res) => {
  const { data: file, error } = await adminDb
    .from("files")
    .select("*")
    .eq("id", req.params.id)
    .eq("owner_id", req.user.id)
    .eq("is_trashed", false)
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  if (!file) return res.status(404).json({ error: "File not found." });

  const { data, error: urlError } = await adminDb.storage
    .from(STORAGE_BUCKET)
    .createSignedUrl(file.storage_path, 300);

  if (urlError) return res.status(400).json({ error: urlError.message });

  await adminDb.from("activity_logs").insert({
    user_id: req.user.id,
    action: "file_downloaded",
    details: { file_id: file.id, name: file.original_name }
  });

  res.json({ url: data.signedUrl, file });
});

app.post("/api/files/:id/trash", requireUser, async (req, res) => {
  const { data: file, error: findError } = await adminDb
    .from("files")
    .select("id,original_name")
    .eq("id", req.params.id)
    .eq("owner_id", req.user.id)
    .eq("is_trashed", false)
    .maybeSingle();

  if (findError) return res.status(500).json({ error: findError.message });
  if (!file) return res.status(404).json({ error: "File not found." });

  const { error } = await adminDb
    .from("files")
    .update({ is_trashed: true, deleted_at: new Date().toISOString() })
    .eq("id", file.id)
    .eq("owner_id", req.user.id);

  if (error) return res.status(400).json({ error: error.message });

  await adminDb.from("activity_logs").insert({
    user_id: req.user.id,
    action: "file_trashed",
    details: { file_id: file.id, name: file.original_name }
  });

  res.json({ ok: true });
});

app.post("/api/files/:id/restore", requireUser, async (req, res) => {
  const { error } = await adminDb
    .from("files")
    .update({ is_trashed: false, deleted_at: null })
    .eq("id", req.params.id)
    .eq("owner_id", req.user.id)
    .eq("is_trashed", true);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

app.delete("/api/files/:id", requireUser, async (req, res) => {
  const { data: file, error: findError } = await adminDb
    .from("files")
    .select("*")
    .eq("id", req.params.id)
    .eq("owner_id", req.user.id)
    .maybeSingle();

  if (findError) return res.status(500).json({ error: findError.message });
  if (!file) return res.status(404).json({ error: "File not found." });

  const { error: storageError } = await adminDb.storage
    .from(STORAGE_BUCKET)
    .remove([file.storage_path]);

  if (storageError) console.warn("Storage deletion warning:", storageError.message);

  const { error } = await adminDb
    .from("files")
    .delete()
    .eq("id", file.id)
    .eq("owner_id", req.user.id);

  if (error) return res.status(400).json({ error: error.message });

  await adminDb.from("activity_logs").insert({
    user_id: req.user.id,
    action: "file_deleted",
    details: { file_id: file.id, name: file.original_name }
  });

  res.json({ ok: true });
});

app.get("/api/clients", requireUser, async (req, res) => {
  const { data, error } = await adminDb
    .from("clients")
    .select("*")
    .eq("owner_id", req.user.id)
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ clients: data || [] });
});

app.post("/api/clients", requireUser, async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 120);
  const description = String(req.body.description || "").trim().slice(0, 500);

  if (!name) return res.status(400).json({ error: "Client name is required." });

  const { data, error } = await adminDb
    .from("clients")
    .insert({ owner_id: req.user.id, name, description })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ client: data });
});

app.get("/api/activity", requireUser, async (req, res) => {
  const { data, error } = await adminDb
    .from("activity_logs")
    .select("*")
    .eq("user_id", req.user.id)
    .order("created_at", { ascending: false })
    .limit(100);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ activity: data || [] });
});

app.post("/api/share", requireUser, async (req, res) => {
  try {
    const { fileId, expiresAt, password, downloadLimit } = req.body;

    const { data: file, error: fileError } = await adminDb
      .from("files")
      .select("id,owner_id,original_name,is_trashed")
      .eq("id", fileId)
      .eq("owner_id", req.user.id)
      .maybeSingle();

    if (fileError) return res.status(500).json({ error: fileError.message });
    if (!file || file.is_trashed) return res.status(404).json({ error: "File not found." });

    const token = randomToken();
    const passwordHash = password ? sha256(String(password)) : null;
    const limit = downloadLimit ? Math.max(1, Math.min(10000, Number(downloadLimit))) : null;

    const { error } = await adminDb.from("share_links").insert({
      owner_id: req.user.id,
      file_id: file.id,
      token_hash: sha256(token),
      password_hash: passwordHash,
      expires_at: expiresAt || null,
      download_limit: limit,
      download_count: 0,
      revoked: false
    });

    if (error) return res.status(400).json({ error: error.message });

    const origin = process.env.PUBLIC_SITE_URL || `${req.protocol}://${req.get("host")}`;
    const url = `${origin}/share/${token}`;

    await adminDb.from("activity_logs").insert({
      user_id: req.user.id,
      action: "share_created",
      details: { file_id: file.id, name: file.original_name }
    });

    res.status(201).json({ url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not create share link." });
  }
});

app.get("/api/share/:token", async (req, res) => {
  try {
    const hash = sha256(req.params.token);

    const { data: link, error } = await adminDb
      .from("share_links")
      .select("id,file_id,owner_id,password_hash,expires_at,download_limit,download_count,revoked")
      .eq("token_hash", hash)
      .maybeSingle();

    if (error) return res.status(500).json({ error: "Share lookup failed." });
    if (!link || link.revoked) return res.status(404).json({ error: "Share link is unavailable." });

    if (link.expires_at && new Date(link.expires_at) <= new Date()) {
      return res.status(410).json({ error: "Share link has expired." });
    }

    if (link.download_limit !== null && link.download_count >= link.download_limit) {
      return res.status(410).json({ error: "Download limit reached." });
    }

    const supplied = req.headers["x-share-password"];
    if (link.password_hash && sha256(String(supplied || "")) !== link.password_hash) {
      return res.status(401).json({ passwordRequired: true, error: "Password required." });
    }

    const { data: file, error: fileError } = await adminDb
      .from("files")
      .select("id,original_name,mime_type,size,storage_path")
      .eq("id", link.file_id)
      .eq("owner_id", link.owner_id)
      .maybeSingle();

    if (fileError || !file) return res.status(404).json({ error: "Shared file not found." });

    const { data: signed, error: signedError } = await adminDb.storage
      .from(STORAGE_BUCKET)
      .createSignedUrl(file.storage_path, 300);

    if (signedError) return res.status(400).json({ error: signedError.message });

    await adminDb
      .from("share_links")
      .update({ download_count: link.download_count + 1 })
      .eq("id", link.id);

    res.json({
      file: {
        name: file.original_name,
        mimeType: file.mime_type,
        size: file.size
      },
      url: signed.signedUrl
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Unable to open share link." });
  }
});

app.get("/api/admin/data", requireAdmin, async (req, res) => {
  const [{ data: users, error: usersError }, { data: files, error: filesError }] = await Promise.all([
    adminDb.from("profiles").select("id,username,email,role,disabled,created_at").order("created_at", { ascending: false }),
    adminDb.from("files").select("id,owner_id,original_name,size,is_trashed,created_at")
  ]);

  if (usersError || filesError) {
    return res.status(500).json({ error: usersError?.message || filesError?.message });
  }

  const storageByUser = {};
  for (const file of files || []) {
    storageByUser[file.owner_id] = (storageByUser[file.owner_id] || 0) + Number(file.size || 0);
  }

  res.json({ users: users || [], files: files || [], storageByUser });
});

app.post("/api/admin/user/:id/disable", requireAdmin, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: "You cannot disable your own admin account." });
  }

  const disabled = Boolean(req.body.disabled);

  const { error: profileError } = await adminDb
    .from("profiles")
    .update({ disabled })
    .eq("id", req.params.id);

  if (profileError) return res.status(400).json({ error: profileError.message });

  const { error: authError } = await adminDb.auth.admin.updateUserById(
    req.params.id,
    { ban_duration: disabled ? "876000h" : "none" }
  );

  if (authError) console.warn("Auth ban update warning:", authError.message);

  res.json({ ok: true });
});

app.delete("/api/admin/user/:id", requireAdmin, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: "You cannot delete your own admin account." });
  }

  const { data: files } = await adminDb
    .from("files")
    .select("storage_path")
    .eq("owner_id", req.params.id);

  if (files?.length) {
    await adminDb.storage.from(STORAGE_BUCKET)
      .remove(files.map(f => f.storage_path));
  }

  const { error } = await adminDb.auth.admin.deleteUser(req.params.id);
  if (error) return res.status(400).json({ error: error.message });

  res.json({ ok: true });
});

app.post("/api/admin/file/:id/delete", requireAdmin, async (req, res) => {
  const { data: file, error } = await adminDb
    .from("files")
    .select("*")
    .eq("id", req.params.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  if (!file) return res.status(404).json({ error: "File not found." });

  await adminDb.storage.from(STORAGE_BUCKET).remove([file.storage_path]);

  const { error: deleteError } = await adminDb
    .from("files")
    .delete()
    .eq("id", file.id);

  if (deleteError) return res.status(400).json({ error: deleteError.message });

  res.json({ ok: true });
});

app.post("/api/bootstrap-admin", async (req, res) => {
  const secret = req.headers["x-bootstrap-secret"];
  if (!process.env.BOOTSTRAP_SECRET || secret !== process.env.BOOTSTRAP_SECRET) {
    return res.status(403).json({ error: "Invalid bootstrap secret." });
  }

  try {
    const username = safeUsername(process.env.ADMIN_USERNAME || "admin");
    const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const password = String(process.env.ADMIN_PASSWORD || "");

    if (!email || password.length < 8) {
      return res.status(500).json({ error: "ADMIN_EMAIL and ADMIN_PASSWORD must be configured." });
    }

    const { data: existing } = await adminDb
      .from("profiles")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (existing) return res.json({ ok: true, message: "Admin already exists." });

    const { data: created, error: createError } = await adminDb.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username }
    });

    if (createError) return res.status(400).json({ error: createError.message });

    const { error: profileError } = await adminDb.from("profiles").insert({
      id: created.user.id,
      username,
      email,
      role: "admin",
      disabled: false
    });

    if (profileError) {
      await adminDb.auth.admin.deleteUser(created.user.id);
      return res.status(500).json({ error: profileError.message });
    }

    res.status(201).json({ ok: true, message: "Admin created." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Admin bootstrap failed." });
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.get("*splat", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API route not found." });
  }
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Data Security running on port ${PORT}`);
});
