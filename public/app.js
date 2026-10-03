"use strict";

const state = {
  supabase: null,
  session: null,
  profile: null,
  config: null,
  files: [],
  trash: [],
  clients: [],
  shares: [],
  activities: [],
  currentPage: "dashboard",
  selectedFile: null,
  editingClientId: null
};

const $ = (id) => document.getElementById(id);

const escapeHtml = (value) => {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
};

function initials(name = "User") {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "U";
  return parts.slice(0, 2).map(x => x[0]).join("").toUpperCase();
}

function formatBytes(bytes = 0) {
  const n = Number(bytes) || 0;

  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "—";

  return date.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function formatShortDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "—";

  return date.toLocaleDateString([], {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
}

function showToast(title, message = "", type = "info") {
  const container = $("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;

  const icon =
    type === "success" ? "✓" :
    type === "error" ? "!" :
    "i";

  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-content">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(message)}</p>
    </div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(15px)";

    setTimeout(() => toast.remove(), 200);
  }, 3500);
}

function setLoading(show) {
  const loader = $("appLoader");
  if (!loader) return;

  loader.classList.toggle("hidden", !show);
}

function setButtonLoading(button, loading, text = "Loading...") {
  if (!button) return;

  if (loading) {
    if (!button.dataset.originalText) {
      button.dataset.originalText = button.textContent;
    }

    button.disabled = true;
    button.textContent = text;
  } else {
    button.disabled = false;

    if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
      delete button.dataset.originalText;
    }
  }
}

/* =========================================================
   API
========================================================= */

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});

  headers.set("Content-Type", "application/json");

  if (state.session?.access_token) {
    headers.set(
      "Authorization",
      `Bearer ${state.session.access_token}`
    );
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  const contentType = response.headers.get("content-type") || "";

  let data;

  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const message =
      typeof data === "object"
        ? data.error || data.message || "Request failed"
        : data || "Request failed";

    throw new Error(message);
  }

  return data;
}

/* =========================================================
   CONFIG
========================================================= */

async function loadConfig() {
  const response = await fetch("/api/config");

  if (!response.ok) {
    throw new Error("Could not load application configuration.");
  }

  const config = await response.json();

  if (!config.supabaseUrl || !config.supabaseAnonKey) {
    throw new Error("Supabase configuration is incomplete.");
  }

  /*
   * Never allow a secret/service-role key in browser code.
   */
  const key = String(config.supabaseAnonKey);

  if (
    key.startsWith("sb_secret_") ||
    key.toLowerCase().includes("service_role")
  ) {
    throw new Error(
      "Server configuration error: a secret Supabase key was sent to the browser."
    );
  }

  state.config = config;

  if (!window.supabase?.createClient) {
    throw new Error("Supabase library failed to load.");
  }

  state.supabase = window.supabase.createClient(
    config.supabaseUrl,
    config.supabaseAnonKey
  );
}

/* =========================================================
   AUTH
========================================================= */

function showAuthScreen() {
  $("mainApp")?.classList.add("hidden");
  $("authScreen")?.classList.remove("hidden");
}

function showMainApp() {
  $("authScreen")?.classList.add("hidden");
  $("mainApp")?.classList.remove("hidden");
}

function switchAuth(mode) {
  const login = $("loginPanel");
  const register = $("registerPanel");

  if (!login || !register) return;

  if (mode === "register") {
    login.classList.add("hidden");
    register.classList.remove("hidden");
  } else {
    register.classList.add("hidden");
    login.classList.remove("hidden");
  }
}

async function loginUser(event) {
  event.preventDefault();

  const button = $("loginButton");

  const identity = $("loginIdentity")?.value.trim();
  const password = $("loginPassword")?.value || "";

  if (!identity || !password) {
    showToast(
      "Missing information",
      "Enter your email/username and password.",
      "error"
    );
    return;
  }

  try {
    setButtonLoading(button, true, "Signing in...");

    const lookup = await api("/api/login-identity", {
      method: "POST",
      body: JSON.stringify({ identity })
    });

    const email = lookup.email;

    if (!email) {
      throw new Error("Unable to find the account.");
    }

    const result = await state.supabase.auth.signInWithPassword({
      email,
      password
    });

    if (result.error) {
      throw result.error;
    }

    state.session = result.data.session;

    await loadUserData();

    showMainApp();

    showToast(
      "Welcome back",
      `Signed in as ${state.profile?.username || email}.`,
      "success"
    );

    $("loginPassword").value = "";

  } catch (error) {
    console.error(error);

    showToast(
      "Login failed",
      error.message || "Unable to sign in.",
      "error"
    );

  } finally {
    setButtonLoading(button, false);
  }
}

async function registerUser(event) {
  event.preventDefault();

  const button = $("registerButton");

  const username = $("registerUsername")?.value.trim();
  const email = $("registerEmail")?.value.trim();
  const password = $("registerPassword")?.value || "";
  const referralCode = $("registerReferral")?.value.trim();

  if (!username || !email || !password) {
    showToast(
      "Missing information",
      "Complete all required fields.",
      "error"
    );
    return;
  }

  if (password.length < 6) {
    showToast(
      "Weak password",
      "Password must contain at least 6 characters.",
      "error"
    );
    return;
  }

  try {
    setButtonLoading(button, true, "Creating account...");

    const result = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        email,
        password,
        referralCode
      })
    });

    if (result.session) {
      state.session = result.session;
    } else {
      const login = await state.supabase.auth.signInWithPassword({
        email,
        password
      });

      if (login.error) {
        throw login.error;
      }

      state.session = login.data.session;
    }

    await loadUserData();

    showMainApp();

    showToast(
      "Account created",
      "Your Data Security account is ready.",
      "success"
    );

    $("registerForm")?.reset();

  } catch (error) {
    console.error(error);

    showToast(
      "Registration failed",
      error.message || "Unable to create account.",
      "error"
    );

  } finally {
    setButtonLoading(button, false);
  }
}

async function logoutUser() {
  try {
    await state.supabase.auth.signOut();
  } catch (error) {
    console.error(error);
  }

  state.session = null;
  state.profile = null;

  showAuthScreen();
  switchAuth("login");

  showToast(
    "Signed out",
    "You have been logged out.",
    "success"
  );
}

/* =========================================================
   USER DATA
========================================================= */

async function loadUserData() {
  const me = await api("/api/me");

  state.profile = me.profile;

  updateUserUI();

  await Promise.all([
    loadFiles(),
    loadTrash(),
    loadClients(),
    loadShares(),
    loadActivities()
  ]);

  updateDashboard();
  renderFiles();
  renderTrash();
  renderClients();
  renderShares();
  renderActivities();
  renderSettings();

  if (state.profile?.role === "admin") {
    $("adminNav")?.classList.remove("hidden");
    await loadAdminData();
  } else {
    $("adminNav")?.classList.add("hidden");
  }
}

function updateUserUI() {
  const profile = state.profile || {};
  const username =
    profile.username ||
    profile.email ||
    "User";

  const avatar = initials(username);

  if ($("userAvatarText")) {
    $("userAvatarText").textContent = avatar;
  }

  if ($("topUsername")) {
    $("topUsername").textContent = username;
  }

  if ($("topEmail")) {
    $("topEmail").textContent = profile.email || "";
  }

  if ($("welcomeUsername")) {
    $("welcomeUsername").textContent = username;
  }

  if ($("settingsUsername")) {
    $("settingsUsername").value = profile.username || "";
  }

  if ($("settingsEmail")) {
    $("settingsEmail").value = profile.email || "";
  }

  if ($("settingsAvatar")) {
    $("settingsAvatar").value = profile.avatar_url || "";
  }

  if ($("accountId")) {
    $("accountId").textContent = profile.id || "—";
  }

  if ($("accountRole")) {
    $("accountRole").textContent =
      profile.role === "admin" ? "Administrator" : "User";
  }

  if ($("accountCreated")) {
    $("accountCreated").textContent =
      formatShortDate(profile.created_at);
  }
}

/* =========================================================
   FILES
========================================================= */

async function loadFiles() {
  const result = await api("/api/files");

  state.files = Array.isArray(result)
    ? result
    : result.files || [];
}

async function loadTrash() {
  const result = await api("/api/files/trash");

  state.trash = Array.isArray(result)
    ? result
    : result.files || [];
}

function fileIcon(file) {
  const mime = String(file.mime_type || "").toLowerCase();
  const name = String(file.name || "").toLowerCase();

  if (mime.startsWith("image/")) return "IMG";
  if (mime.startsWith("video/")) return "VID";
  if (mime.startsWith("audio/")) return "AUD";
  if (mime.includes("pdf") || name.endsWith(".pdf")) return "PDF";
  if (
    mime.includes("zip") ||
    mime.includes("rar") ||
    mime.includes("7z")
  ) {
    return "ZIP";
  }

  if (
    mime.includes("word") ||
    name.endsWith(".doc") ||
    name.endsWith(".docx")
  ) {
    return "DOC";
  }

  if (
    mime.includes("sheet") ||
    name.endsWith(".xls") ||
    name.endsWith(".xlsx") ||
    name.endsWith(".csv")
  ) {
    return "XLS";
  }

  if (
    mime.includes("text") ||
    name.endsWith(".txt") ||
    name.endsWith(".json") ||
    name.endsWith(".js") ||
    name.endsWith(".css") ||
    name.endsWith(".html")
  ) {
    return "TXT";
  }

  return "FILE";
}

function getClientName(clientId) {
  if (!clientId) return "";

  const client = state.clients.find(
    c => c.id === clientId
  );

  return client?.name || "";
}

function renderFileCard(file, options = {}) {
  const deleted = Boolean(options.deleted);

  const description =
    file.description ||
    "No description";

  const clientName =
    file.client_name ||
    getClientName(file.client_id);

  const icon = fileIcon(file);

  return `
    <article class="file-card">
      <div class="file-top">
        <div class="file-type-icon">
          ${escapeHtml(icon)}
        </div>

        <button
          class="file-menu"
          type="button"
          title="File options"
          data-file-menu="${escapeHtml(file.id)}"
        >
          •••
        </button>
      </div>

      <div class="file-name" title="${escapeHtml(file.name)}">
        ${escapeHtml(file.name)}
      </div>

      <div class="file-description">
        ${escapeHtml(description)}
      </div>

      <div class="file-meta">
        <span class="meta-pill">
          ${escapeHtml(formatBytes(file.size_bytes))}
        </span>

        <span class="meta-pill">
          ${escapeHtml(formatShortDate(file.created_at))}
        </span>

        ${
          clientName
            ? `<span class="meta-pill">${escapeHtml(clientName)}</span>`
            : ""
        }
      </div>

      <div class="file-actions">
        ${
          deleted
            ? `
              <button
                class="btn btn-success"
                type="button"
                data-restore-file="${escapeHtml(file.id)}"
              >
                Restore
              </button>

              <button
                class="btn btn-danger"
                type="button"
                data-delete-permanent="${escapeHtml(file.id)}"
              >
                Delete
              </button>
            `
            : `
              <button
                class="btn btn-secondary"
                type="button"
                data-download-file="${escapeHtml(file.id)}"
              >
                Download
              </button>

              <button
                class="btn btn-primary"
                type="button"
                data-share-file="${escapeHtml(file.id)}"
              >
                Share
              </button>

              <button
                class="btn btn-danger"
                type="button"
                data-trash-file="${escapeHtml(file.id)}"
              >
                Trash
              </button>
            `
        }
      </div>
    </article>
  `;
}

function renderFiles() {
  const container = $("filesContainer");
  if (!container) return;

  const search =
    $("fileSearch")?.value.trim().toLowerCase() || "";

  const sort =
    $("fileSort")?.value || "newest";

  let files = [...state.files];

  if (search) {
    files = files.filter(file => {
      const text = [
        file.name,
        file.description,
        file.mime_type,
        getClientName(file.client_id)
      ]
        .join(" ")
        .toLowerCase();

      return text.includes(search);
    });
  }

  files.sort((a, b) => {
    if (sort === "oldest") {
      return new Date(a.created_at) - new Date(b.created_at);
    }

    if (sort === "name") {
      return String(a.name).localeCompare(String(b.name));
    }

    if (sort === "largest") {
      return Number(b.size_bytes || 0) -
        Number(a.size_bytes || 0);
    }

    return new Date(b.created_at) - new Date(a.created_at);
  });

  if (!files.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">▣</div>
        <h3>No files found</h3>
        <p>
          Upload your first file to start using your private
          Data Security storage.
        </p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="file-grid">
      ${files.map(file => renderFileCard(file)).join("")}
    </div>
  `;
}

function renderRecentFiles() {
  const container = $("recentFiles");
  if (!container) return;

  const recent = [...state.files]
    .sort(
      (a, b) =>
        new Date(b.created_at) -
        new Date(a.created_at)
    )
    .slice(0, 5);

  if (!recent.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">▣</div>
        <h3>No recent files</h3>
        <p>Your uploaded files will appear here.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="file-grid">
      ${recent.map(file => renderFileCard(file)).join("")}
    </div>
  `;
}

async function downloadFile(fileId) {
  try {
    const response = await fetch(
      `/api/files/${encodeURIComponent(fileId)}/download`,
      {
        headers: {
          Authorization:
            `Bearer ${state.session.access_token}`
        }
      }
    );

    if (!response.ok) {
      let message = "Download failed.";

      try {
        const data = await response.json();
        message = data.error || message;
      } catch (_) {}

      throw new Error(message);
    }

    const blob = await response.blob();

    const disposition =
      response.headers.get("Content-Disposition") || "";

    let filename = "download";

    const match = disposition.match(
      /filename="?([^"]+)"?/i
    );

    if (match?.[1]) {
      filename = match[1];
    } else {
      const file = state.files.find(
        item => item.id === fileId
      );

      if (file?.name) {
        filename = file.name;
      }
    }

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 2000);

  } catch (error) {
    console.error(error);

    showToast(
      "Download failed",
      error.message,
      "error"
    );
  }
}

async function moveToTrash(fileId) {
  try {
    await api(`/api/files/${fileId}/trash`, {
      method: "POST"
    });

    await loadFiles();
    await loadTrash();

    renderFiles();
    renderTrash();
    updateDashboard();

    showToast(
      "File moved",
      "The file was moved to Trash.",
      "success"
    );

  } catch (error) {
    showToast(
      "Unable to move file",
      error.message,
      "error"
    );
  }
}

async function restoreFile(fileId) {
  try {
    await api(`/api/files/${fileId}/restore`, {
      method: "POST"
    });

    await loadFiles();
    await loadTrash();

    renderFiles();
    renderTrash();
    updateDashboard();

    showToast(
      "File restored",
      "The file has been restored.",
      "success"
    );

  } catch (error) {
    showToast(
      "Restore failed",
      error.message,
      "error"
    );
  }
}

async function permanentlyDeleteFile(fileId) {
  const confirmed = window.confirm(
    "Permanently delete this file? This action cannot be undone."
  );

  if (!confirmed) return;

  try {
    await api(`/api/files/${fileId}/permanent`, {
      method: "DELETE"
    });

    await loadTrash();

    renderTrash();
    updateDashboard();

    showToast(
      "File deleted",
      "The file was permanently deleted.",
      "success"
    );

  } catch (error) {
    showToast(
      "Delete failed",
      error.message,
      "error"
    );
  }
}

/* =========================================================
   UPLOAD
========================================================= */

function selectUploadFile(file) {
  if (!file) return;

  const maxBytes =
    Number(state.config?.maxFileSizeBytes) ||
    Number(state.config?.maxFileSizeMB || 100) *
      1024 *
      1024;

  if (file.size > maxBytes) {
    showToast(
      "File too large",
      `Maximum allowed size is ${formatBytes(maxBytes)}.`,
      "error"
    );

    return;
  }

  state.selectedFile = file;

  $("selectedFileBox")?.classList.remove("hidden");

  if ($("selectedFileName")) {
    $("selectedFileName").textContent = file.name;
  }

  if ($("selectedFileSize")) {
    $("selectedFileSize").textContent =
      formatBytes(file.size);
  }
}

function clearSelectedFile() {
  state.selectedFile = null;

  if ($("fileInput")) {
    $("fileInput").value = "";
  }

  $("selectedFileBox")?.classList.add("hidden");

  if ($("selectedFileName")) {
    $("selectedFileName").textContent = "";
  }

  if ($("selectedFileSize")) {
    $("selectedFileSize").textContent = "";
  }
}

async function uploadSelectedFile(event) {
  event?.preventDefault();

  const file = state.selectedFile;

  if (!file) {
    showToast(
      "No file selected",
      "Choose a file first.",
      "error"
    );
    return;
  }

  const button = $("uploadSubmitButton");

  try {
    setButtonLoading(button, true, "Uploading...");

    setUploadProgress(5, "Preparing upload...");

    const sessionResult =
      await state.supabase.auth.getSession();

    const session =
      sessionResult.data.session || state.session;

    if (!session) {
      throw new Error("Your session has expired.");
    }

    state.session = session;

    const safeName = file.name
      .replace(/[^\w.\-() ]+/g, "_")
      .replace(/\s+/g, "_")
      .slice(0, 180);

    const unique =
      typeof crypto !== "undefined" &&
      typeof crypto.randomUUID === "function"
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}`;

    const storagePath =
      `${session.user.id}/${unique}-${safeName}`;

    setUploadProgress(
      15,
      "Uploading file..."
    );

    const uploadResult =
      await state.supabase.storage
        .from(state.config.storageBucket)
        .upload(storagePath, file, {
          cacheControl: "3600",
          upsert: false,
          contentType:
            file.type || "application/octet-stream"
        });

    if (uploadResult.error) {
      throw uploadResult.error;
    }

    setUploadProgress(
      75,
      "Saving file information..."
    );

    const description =
      $("uploadDescription")?.value.trim() || "";

    const clientId =
      $("uploadClient")?.value || null;

    try {
      await api("/api/files/register", {
        method: "POST",
        body: JSON.stringify({
          name: file.name,
          storagePath,
          mimeType:
            file.type || "application/octet-stream",
          sizeBytes: file.size,
          description,
          clientId
        })
      });

    } catch (error) {
      /*
       * If database registration fails after storage upload,
       * attempt to remove the orphaned storage object.
       */
      try {
        await state.supabase.storage
          .from(state.config.storageBucket)
          .remove([storagePath]);
      } catch (_) {}

      throw error;
    }

    setUploadProgress(
      100,
      "Upload complete."
    );

    await loadFiles();

    renderFiles();
    renderRecentFiles();
    updateDashboard();

    showToast(
      "Upload complete",
      `${file.name} was uploaded successfully.`,
      "success"
    );

    $("uploadDescription").value = "";
    $("uploadClient").value = "";

    clearSelectedFile();

    setTimeout(() => {
      setUploadProgress(0, "");
    }, 500);

  } catch (error) {
    console.error(error);

    showToast(
      "Upload failed",
      error.message || "Unable to upload the file.",
      "error"
    );

    setUploadProgress(0, "");
  } finally {
    setButtonLoading(button, false);
  }
}

function setUploadProgress(percent, text) {
  const box = $("uploadProgressBox");

  if (box) {
    box.classList.toggle(
      "hidden",
      !text && percent === 0
    );
  }

  if ($("uploadProgressText")) {
    $("uploadProgressText").textContent =
      text || `${percent}%`;
  }

  if ($("uploadProgressBar")) {
    $("uploadProgressBar").style.width =
      `${Math.max(0, Math.min(100, percent))}%`;
  }
}

function populateUploadClients() {
  const select = $("uploadClient");

  if (!select) return;

  select.innerHTML = `
    <option value="">No client</option>
    ${state.clients
      .map(client => `
        <option value="${escapeHtml(client.id)}">
          ${escapeHtml(client.name)}
        </option>
      `)
      .join("")}
  `;
}

/* =========================================================
   CLIENTS
========================================================= */

async function loadClients() {
  const result = await api("/api/clients");

  state.clients = Array.isArray(result)
    ? result
    : result.clients || [];

  populateUploadClients();
}

function renderClients() {
  const container = $("clientsContainer");
  if (!container) return;

  if (!state.clients.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">♙</div>
        <h3>No clients yet</h3>
        <p>
          Add clients to organize files and connect
          uploaded documents to them.
        </p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="client-grid">
      ${state.clients.map(client => `
        <article class="client-card">
          <div class="client-head">
            <div class="client-avatar">
              ${escapeHtml(initials(client.name))}
            </div>

            <div class="client-info">
              <strong>${escapeHtml(client.name)}</strong>
              <span>${escapeHtml(client.email || "No email")}</span>
            </div>
          </div>

          <div class="client-details">
            ${
              client.phone
                ? `
                  <div class="client-detail">
                    <strong>Phone:</strong>
                    <span>${escapeHtml(client.phone)}</span>
                  </div>
                `
                : ""
            }

            ${
              client.notes
                ? `
                  <div class="client-detail">
                    <strong>Notes:</strong>
                    <span>${escapeHtml(client.notes)}</span>
                  </div>
                `
                : ""
            }
          </div>

          <div class="client-actions">
            <button
              class="btn btn-secondary"
              type="button"
              data-edit-client="${escapeHtml(client.id)}"
            >
              Edit
            </button>

            <button
              class="btn btn-danger"
              type="button"
              data-delete-client="${escapeHtml(client.id)}"
            >
              Delete
            </button>
          </div>
        </article>
      `).join("")}
    </div>
  `;
}

function openClientModal(client = null) {
  const modal = $("clientModal");
  if (!modal) return;

  state.editingClientId = client?.id || null;

  if ($("clientModalTitle")) {
    $("clientModalTitle").textContent =
      client ? "Edit Client" : "Add Client";
  }

  if ($("clientId")) {
    $("clientId").value = client?.id || "";
  }

  if ($("clientName")) {
    $("clientName").value = client?.name || "";
  }

  if ($("clientEmail")) {
    $("clientEmail").value = client?.email || "";
  }

  if ($("clientPhone")) {
    $("clientPhone").value = client?.phone || "";
  }

  if ($("clientNotes")) {
    $("clientNotes").value = client?.notes || "";
  }

  modal.classList.add("show");
}

function closeModal(id) {
  $(id)?.classList.remove("show");
}

async function saveClient(event) {
  event.preventDefault();

  const id = $("clientId")?.value || "";

  const data = {
    name: $("clientName")?.value.trim(),
    email: $("clientEmail")?.value.trim(),
    phone: $("clientPhone")?.value.trim(),
    notes: $("clientNotes")?.value.trim()
  };

  if (!data.name) {
    showToast(
      "Client name required",
      "Enter the client's name.",
      "error"
    );
    return;
  }

  try {
    if (id) {
      await api(`/api/clients/${id}`, {
        method: "PUT",
        body: JSON.stringify(data)
      });

      showToast(
        "Client updated",
        "Client information was updated.",
        "success"
      );

    } else {
      await api("/api/clients", {
        method: "POST",
        body: JSON.stringify(data)
      });

      showToast(
        "Client added",
        "New client was created.",
        "success"
      );
    }

    closeModal("clientModal");

    await loadClients();

    renderClients();
    updateDashboard();

  } catch (error) {
    showToast(
      "Client operation failed",
      error.message,
      "error"
    );
  }
}

async function deleteClient(clientId) {
  const confirmed = window.confirm(
    "Delete this client?"
  );

  if (!confirmed) return;

  try {
    await api(`/api/clients/${clientId}`, {
      method: "DELETE"
    });

    await loadClients();

    renderClients();
    updateDashboard();

    showToast(
      "Client deleted",
      "The client was removed.",
      "success"
    );

  } catch (error) {
    showToast(
      "Delete failed",
      error.message,
      "error"
    );
  }
}

/* =========================================================
   SHARES
========================================================= */

async function loadShares() {
  const result = await api("/api/shares");

  state.shares = Array.isArray(result)
    ? result
    : result.shares || [];
}

function renderShares() {
  const container = $("sharedContainer");
  if (!container) return;

  if (!state.shares.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">↗</div>
        <h3>No shared files</h3>
        <p>
          Generate a share link from a file to see it here.
        </p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="card">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>File</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            ${state.shares.map(share => {
              const expired =
                share.expires_at &&
                new Date(share.expires_at) < new Date();

              const revoked =
                Boolean(share.revoked_at);

              const status =
                revoked
                  ? `<span class="status status-danger">Revoked</span>`
                  : expired
                    ? `<span class="status status-warning">Expired</span>`
                    : `<span class="status status-success">Active</span>`;

              return `
                <tr>
                  <td>
                    ${escapeHtml(
                      share.file_name ||
                      share.files?.name ||
                      "File"
                    )}
                  </td>

                  <td>
                    ${escapeHtml(
                      formatShortDate(share.created_at)
                    )}
                  </td>

                  <td>
                    ${escapeHtml(
                      share.expires_at
                        ? formatShortDate(share.expires_at)
                        : "Never"
                    )}
                  </td>

                  <td>${status}</td>

                  <td>
                    ${
                      !revoked && !expired
                        ? `
                          <button
                            class="btn btn-danger"
                            type="button"
                            data-revoke-share="${escapeHtml(share.id)}"
                          >
                            Revoke
                          </button>
                        `
                        : "—"
                    }
                  </td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function openShareModal(fileId) {
  const modal = $("shareModal");
  if (!modal) return;

  if ($("shareFileId")) {
    $("shareFileId").value = fileId;
  }

  if ($("shareExpiration")) {
    $("shareExpiration").value = "7";
  }

  $("generatedShareBox")?.classList.add("hidden");

  if ($("generatedShareUrl")) {
    $("generatedShareUrl").textContent = "";
  }

  modal.classList.add("show");
}

async function generateShare() {
  const fileId =
    $("shareFileId")?.value;

  const expiration =
    $("shareExpiration")?.value || "7";

  if (!fileId) {
    showToast(
      "No file selected",
      "Select a file to share.",
      "error"
    );
    return;
  }

  const button = $("generateShareButton");

  try {
    setButtonLoading(
      button,
      true,
      "Generating..."
    );

    const result = await api("/api/shares", {
      method: "POST",
      body: JSON.stringify({
        fileId,
        expirationDays:
          expiration === "never"
            ? null
            : Number(expiration)
      })
    });

    const token =
      result.token ||
      result.share?.token;

    const directUrl =
      result.url ||
      (token
        ? `${window.location.origin}/share/${encodeURIComponent(token)}`
        : "");

    if (!directUrl) {
      throw new Error(
        "The server did not return a share URL."
      );
    }

    $("generatedShareBox")?.classList.remove("hidden");

    if ($("generatedShareUrl")) {
      $("generatedShareUrl").textContent =
        directUrl;
    }

    await loadShares();

    renderShares();

    showToast(
      "Share link created",
      "The share link is ready.",
      "success"
    );

  } catch (error) {
    showToast(
      "Share failed",
      error.message,
      "error"
    );
  } finally {
    setButtonLoading(
      button,
      false
    );
  }
}

async function revokeShare(shareId) {
  const confirmed = window.confirm(
    "Revoke this share link?"
  );

  if (!confirmed) return;

  try {
    await api(`/api/shares/${shareId}`, {
      method: "DELETE"
    });

    await loadShares();

    renderShares();

    showToast(
      "Share revoked",
      "The link can no longer be used.",
      "success"
    );

  } catch (error) {
    showToast(
      "Unable to revoke",
      error.message,
      "error"
    );
  }
}

async function copyGeneratedShare() {
  const url =
    $("generatedShareUrl")?.textContent;

  if (!url) return;

  try {
    await navigator.clipboard.writeText(url);

    showToast(
      "Copied",
      "Share link copied to clipboard.",
      "success"
    );

  } catch (_) {
    showToast(
      "Copy failed",
      "Your browser blocked clipboard access.",
      "error"
    );
  }
}

/* =========================================================
   ACTIVITY
========================================================= */

async function loadActivities() {
  const result = await api("/api/activity");

  state.activities = Array.isArray(result)
    ? result
    : result.activities || [];
}

function activityIcon(action = "") {
  const value = action.toLowerCase();

  if (value.includes("upload")) return "↑";
  if (value.includes("download")) return "↓";
  if (value.includes("delete")) return "×";
  if (value.includes("trash")) return "×";
  if (value.includes("restore")) return "↶";
  if (value.includes("share")) return "↗";
  if (value.includes("client")) return "♙";
  if (value.includes("login")) return "→";

  return "•";
}

function renderActivities() {
  const container = $("activityContainer");
  if (!container) return;

  if (!state.activities.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">◷</div>
        <h3>No activity yet</h3>
        <p>Your account activity will appear here.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="card">
      <div class="card-body">
        <div class="activity-list">
          ${state.activities.map(activity => {
            const action =
              activity.action ||
              "Activity";

            let details = "";

            if (
              typeof activity.details === "string"
            ) {
              details = activity.details;
            } else if (
              activity.details &&
              typeof activity.details === "object"
            ) {
              details =
                activity.details.message ||
                activity.details.name ||
                JSON.stringify(
                  activity.details
                );
            }

            return `
              <div class="activity-item">
                <div class="activity-dot">
                  ${escapeHtml(
                    activityIcon(action)
                  )}
                </div>

                <div class="activity-content">
                  <strong>
                    ${escapeHtml(action)}
                  </strong>

                  ${
                    details
                      ? `
                        <p>
                          ${escapeHtml(details)}
                        </p>
                      `
                      : ""
                  }

                  <div class="activity-time">
                    ${escapeHtml(
                      formatDate(
                        activity.created_at
                      )
                    )}
                  </div>
                </div>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    </div>
  `;
}

/* =========================================================
   TRASH
========================================================= */

function renderTrash() {
  const container = $("trashContainer");
  if (!container) return;

  if (!state.trash.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⌫</div>
        <h3>Trash is empty</h3>
        <p>Deleted files will appear here.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="file-grid">
      ${state.trash
        .map(file =>
          renderFileCard(file, {
            deleted: true
          })
        )
        .join("")}
    </div>
  `;
}

/* =========================================================
   DASHBOARD
========================================================= */

function updateDashboard() {
  const totalFiles =
    state.files.length;

  const totalStorage =
    state.files.reduce(
      (sum, file) =>
        sum + Number(file.size_bytes || 0),
      0
    );

  const totalClients =
    state.clients.length;

  const activeShares =
    state.shares.filter(share => {
      if (share.revoked_at) return false;

      if (
        share.expires_at &&
        new Date(share.expires_at) < new Date()
      ) {
        return false;
      }

      return true;
    }).length;

  if ($("statFiles")) {
    $("statFiles").textContent =
      totalFiles.toLocaleString();
  }

  if ($("statStorage")) {
    $("statStorage").textContent =
      formatBytes(totalStorage);
  }

  if ($("statClients")) {
    $("statClients").textContent =
      totalClients.toLocaleString();
  }

  if ($("statShared")) {
    $("statShared").textContent =
      activeShares.toLocaleString();
  }

  renderRecentFiles();
}

/* =========================================================
   SETTINGS
========================================================= */

function renderSettings() {
  const profile = state.profile;

  if (!profile) return;

  if ($("settingsUsername")) {
    $("settingsUsername").value =
      profile.username || "";
  }

  if ($("settingsEmail")) {
    $("settingsEmail").value =
      profile.email || "";
  }

  if ($("settingsAvatar")) {
    $("settingsAvatar").value =
      profile.avatar_url || "";
  }

  if ($("accountId")) {
    $("accountId").textContent =
      profile.id || "—";
  }

  if ($("accountRole")) {
    $("accountRole").textContent =
      profile.role === "admin"
        ? "Administrator"
        : "User";
  }

  if ($("accountCreated")) {
    $("accountCreated").textContent =
      formatShortDate(profile.created_at);
  }
}

async function saveProfile(event) {
  event.preventDefault();

  const username =
    $("settingsUsername")?.value.trim();

  const avatarUrl =
    $("settingsAvatar")?.value.trim();

  if (!username) {
    showToast(
      "Username required",
      "Enter a username.",
      "error"
    );
    return;
  }

  try {
    const result = await api("/api/profile", {
      method: "PUT",
      body: JSON.stringify({
        username,
        avatarUrl
      })
    });

    state.profile =
      result.profile || {
        ...state.profile,
        username,
        avatar_url: avatarUrl
      };

    updateUserUI();
    renderSettings();

    showToast(
      "Profile updated",
      "Your profile has been saved.",
      "success"
    );

  } catch (error) {
    showToast(
      "Update failed",
      error.message,
      "error"
    );
  }
}

/* =========================================================
   ADMIN
========================================================= */

async function loadAdminData() {
  if (state.profile?.role !== "admin") {
    return;
  }

  try {
    const [
      stats,
      users,
      files,
      shares
    ] = await Promise.all([
      api("/api/admin/stats"),
      api("/api/admin/users"),
      api("/api/admin/files"),
      api("/api/admin/shares")
    ]);

    renderAdminStats(stats);
    renderAdminUsers(
      Array.isArray(users)
        ? users
        : users.users || []
    );

    renderAdminFiles(
      Array.isArray(files)
        ? files
        : files.files || []
    );

    renderAdminShares(
      Array.isArray(shares)
        ? shares
        : shares.shares || []
    );

  } catch (error) {
    console.error("Admin load failed:", error);

    showToast(
      "Admin data unavailable",
      error.message,
      "error"
    );
  }
}

function renderAdminStats(stats = {}) {
  const values = {
    users:
      stats.users ??
      stats.totalUsers ??
      0,

    files:
      stats.files ??
      stats.totalFiles ??
      0,

    storage:
      stats.storage ??
      stats.totalStorage ??
      0,

    shares:
      stats.shares ??
      stats.totalShares ??
      0
  };

  if ($("adminUsers")) {
    $("adminUsers").textContent =
      Number(values.users).toLocaleString();
  }

  if ($("adminFiles")) {
    $("adminFiles").textContent =
      Number(values.files).toLocaleString();
  }

  if ($("adminStorage")) {
    $("adminStorage").textContent =
      formatBytes(values.storage);
  }

  if ($("adminShares")) {
    $("adminShares").textContent =
      Number(values.shares).toLocaleString();
  }
}

function renderAdminUsers(users) {
  const container = $("adminUsersContainer");
  if (!container) return;

  if (!users.length) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No users</h3>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
            <th>Created</th>
          </tr>
        </thead>

        <tbody>
          ${users.map(user => `
            <tr>
              <td>${escapeHtml(user.username || "—")}</td>
              <td>${escapeHtml(user.email || "—")}</td>
              <td>
                <span class="status ${
                  user.role === "admin"
                    ? "status-warning"
                    : "status-success"
                }">
                  ${escapeHtml(user.role || "user")}
                </span>
              </td>
              <td>
                ${escapeHtml(
                  formatShortDate(user.created_at)
                )}
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderAdminFiles(files) {
  const container = $("adminFilesContainer");
  if (!container) return;

  if (!files.length) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No files</h3>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>File</th>
            <th>User</th>
            <th>Size</th>
            <th>Date</th>
          </tr>
        </thead>

        <tbody>
          ${files.map(file => `
            <tr>
              <td>
                ${escapeHtml(file.name || "—")}
              </td>

              <td>
                ${escapeHtml(
                  file.username ||
                  file.user_email ||
                  file.user_id ||
                  "—"
                )}
              </td>

              <td>
                ${escapeHtml(
                  formatBytes(file.size_bytes)
                )}
              </td>

              <td>
                ${escapeHtml(
                  formatShortDate(file.created_at)
                )}
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderAdminShares(shares) {
  const container = $("adminSharesContainer");

  if (!container) return;

  if (!shares.length) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No shares</h3>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>File</th>
            <th>User</th>
            <th>Created</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          ${shares.map(share => {
            const expired =
              share.expires_at &&
              new Date(share.expires_at) < new Date();

            const revoked =
              Boolean(share.revoked_at);

            return `
              <tr>
                <td>
                  ${escapeHtml(
                    share.file_name ||
                    "—"
                  )}
                </td>

                <td>
                  ${escapeHtml(
                    share.user_email ||
                    share.user_id ||
                    "—"
                  )}
                </td>

                <td>
                  ${escapeHtml(
                    formatShortDate(
                      share.created_at
                    )
                  )}
                </td>

                <td>
                  ${
                    revoked
                      ? `<span class="status status-danger">Revoked</span>`
                      : expired
                        ? `<span class="status status-warning">Expired</span>`
                        : `<span class="status status-success">Active</span>`
                  }
                </td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>
  `;
}

/* =========================================================
   NAVIGATION
========================================================= */

function navigate(page) {
  if (!page) return;

  const target =
    $(`page-${page}`);

  if (!target) return;

  document
    .querySelectorAll(".page")
    .forEach(item => {
      item.classList.remove("active");
    });

  target.classList.add("active");

  document
    .querySelectorAll(".nav-item[data-page]")
    .forEach(item => {
      item.classList.toggle(
        "active",
        item.dataset.page === page
      );
    });

  state.currentPage = page;

  const titles = {
    dashboard: [
      "Dashboard",
      "Overview of your secure storage"
    ],

    files: [
      "My Files",
      "Manage your uploaded files"
    ],

    upload: [
      "Upload File",
      "Securely upload a file to your storage"
    ],

    clients: [
      "Clients",
           "Manage your clients"
    ],

    shared: [
      "Shared Files",
      "Manage your active share links"
    ],

    trash: [
      "Trash",
      "Restore or permanently delete files"
    ],

    activity: [
      "Activity",
      "Recent account activity"
    ],

    settings: [
      "Settings",
      "Manage your account profile"
    ],

    admin: [
      "Administration",
      "System overview and management"
    ]
  };

  const info =
    titles[page] ||
    titles.dashboard;

  if ($("pageTitle")) {
    $("pageTitle").textContent =
      info[0];
  }

  if ($("pageSubtitle")) {
    $("pageSubtitle").textContent =
      info[1];
  }

  closeSidebar();
}

function openSidebar() {
  $("sidebar")?.classList.add("open");
  $("sidebarOverlay")?.classList.add("show");
}

function closeSidebar() {
  $("sidebar")?.classList.remove("open");
  $("sidebarOverlay")?.classList.remove("show");
}

/* =========================================================
   PUBLIC SHARE
========================================================= */

async function checkPublicShare() {
  const match =
    window.location.pathname.match(
      /^\/share\/([^/]+)/
    );

  if (!match) {
    return false;
  }

  const token =
    decodeURIComponent(match[1]);

  document.body.innerHTML = `
    <div class="auth-screen">
      <div class="card" style="
        width:min(520px,100%);
        padding:30px;
        text-align:center;
      ">
        <div class="upload-icon">
          ↗
        </div>

        <h2 id="publicShareTitle">
          Loading shared file...
        </h2>

        <p
          id="publicShareMessage"
          style="
            margin-top:8px;
            color:#8f9bad;
            font-size:12px;
            line-height:1.6;
          "
        >
          Please wait.
        </p>

        <div
          id="publicShareActions"
          style="
            margin-top:20px;
          "
        ></div>
      </div>
    </div>
  `;

  try {
    const result =
      await fetch(
        `/api/public-share/${encodeURIComponent(token)}`
      );

    const data =
      await result.json();

    if (!result.ok) {
      throw new Error(
        data.error ||
        "This share link is unavailable."
      );
    }

    const file =
      data.file ||
      data;

    $("publicShareTitle").textContent =
      file.name || "Shared file";

    $("publicShareMessage").textContent =
      file.description ||
      "This file has been shared with you.";

    $("publicShareActions").innerHTML = `
      <a
        class="btn btn-primary"
        href="${escapeHtml(
          data.downloadUrl ||
          `/api/public-share/${encodeURIComponent(token)}/download`
        )}"
      >
        Download File
      </a>
    `;

  } catch (error) {
    $("publicShareTitle").textContent =
      "Share unavailable";

    $("publicShareMessage").textContent =
      error.message ||
      "This share link is invalid, expired, or revoked.";

    $("publicShareActions").innerHTML = `
      <a
        class="btn btn-secondary"
        href="/"
      >
        Back to Data Security
      </a>
    `;
  }

  return true;
}

/* =========================================================
   EVENTS
========================================================= */

function bindEvents() {
  $("showRegister")?.addEventListener(
    "click",
    () => switchAuth("register")
  );

  $("showLogin")?.addEventListener(
    "click",
    () => switchAuth("login")
  );

  $("loginForm")?.addEventListener(
    "submit",
    loginUser
  );

  $("registerForm")?.addEventListener(
    "submit",
    registerUser
  );

  $("logoutButton")?.addEventListener(
    "click",
    logoutUser
  );

  $("mobileMenuButton")?.addEventListener(
    "click",
    openSidebar
  );

  $("sidebarOverlay")?.addEventListener(
    "click",
    closeSidebar
  );

  document
    .querySelectorAll(".nav-item[data-page]")
    .forEach(button => {
      button.addEventListener(
        "click",
        () => navigate(button.dataset.page)
      );
    });

  $("topUploadButton")?.addEventListener(
    "click",
    () => navigate("upload")
  );

  $("fileSearch")?.addEventListener(
    "input",
    renderFiles
  );

  $("fileSort")?.addEventListener(
    "change",
    renderFiles
  );

  $("chooseFileButton")?.addEventListener(
    "click",
    () => $("fileInput")?.click()
  );

  $("fileInput")?.addEventListener(
    "change",
    event => {
      selectUploadFile(
        event.target.files?.[0]
      );
    }
  );

  $("removeSelectedFile")?.addEventListener(
    "click",
    clearSelectedFile
  );

  $("uploadSubmitButton")?.closest("form")
    ?.addEventListener(
      "submit",
      uploadSelectedFile
    );

  $("dropZone")?.addEventListener(
    "dragover",
    event => {
      event.preventDefault();
      $("dropZone")?.classList.add("dragover");
    }
  );

  $("dropZone")?.addEventListener(
    "dragleave",
    () => {
      $("dropZone")?.classList.remove("dragover");
    }
  );

  $("dropZone")?.addEventListener(
    "drop",
    event => {
      event.preventDefault();

      $("dropZone")?.classList.remove("dragover");

      const file =
        event.dataTransfer?.files?.[0];

      selectUploadFile(file);
    }
  );

  $("addClientButton")?.addEventListener(
    "click",
    () => openClientModal()
  );

  $("clientForm")?.addEventListener(
    "submit",
    saveClient
  );

  $("generateShareButton")?.addEventListener(
    "click",
    generateShare
  );

  $("copyShareButton")?.addEventListener(
    "click",
    copyGeneratedShare
  );

  $("profileForm")?.addEventListener(
    "submit",
    saveProfile
  );

  document
    .querySelectorAll("[data-close-modal]")
    .forEach(button => {
      button.addEventListener(
        "click",
        () => {
          const id =
            button.dataset.closeModal;

          if (id) {
            closeModal(id);
          }
        }
      );
    });

  document
    .querySelectorAll(".modal-overlay")
    .forEach(overlay => {
      overlay.addEventListener(
        "click",
        event => {
          if (event.target === overlay) {
            overlay.classList.remove("show");
          }
        }
      );
    });

  /*
   * Dynamic buttons.
   */
  document.addEventListener(
    "click",
    async event => {
      const target =
        event.target.closest("button");

      if (!target) return;

      const downloadId =
        target.dataset.downloadFile;

      if (downloadId) {
        await downloadFile(downloadId);
        return;
      }

      const trashId =
        target.dataset.trashFile;

      if (trashId) {
        await moveToTrash(trashId);
        return;
      }

      const restoreId =
        target.dataset.restoreFile;

      if (restoreId) {
        await restoreFile(restoreId);
        return;
      }

      const permanentId =
        target.dataset.deletePermanent;

      if (permanentId) {
        await permanentlyDeleteFile(
          permanentId
        );
        return;
      }

      const editClientId =
        target.dataset.editClient;

      if (editClientId) {
        const client =
          state.clients.find(
            item => item.id === editClientId
          );

        if (client) {
          openClientModal(client);
        }

        return;
      }

      const deleteClientId =
        target.dataset.deleteClient;

      if (deleteClientId) {
        await deleteClient(deleteClientId);
        return;
      }

      const shareFileId =
        target.dataset.shareFile;

      if (shareFileId) {
        openShareModal(shareFileId);
        return;
      }

      const revokeShareId =
        target.dataset.revokeShare;

      if (revokeShareId) {
        await revokeShare(revokeShareId);
        return;
      }
    }
  );

  /*
   * Close menus/modals with Escape.
   */
  document.addEventListener(
    "keydown",
    event => {
      if (event.key !== "Escape") return;

      document
        .querySelectorAll(".modal-overlay.show")
        .forEach(modal => {
          modal.classList.remove("show");
        });

      closeSidebar();
    }
  );
}

/* =========================================================
   INITIALIZATION
========================================================= */

async function init() {
  try {
    /*
     * Public share pages don't need normal login.
     */
    if (
      window.location.pathname.startsWith(
        "/share/"
      )
    ) {
      await checkPublicShare();
      setLoading(false);
      return;
    }

    await loadConfig();

    bindEvents();

    const auth =
      await state.supabase.auth.getSession();

    state.session =
      auth.data.session || null;

    state.supabase.auth.onAuthStateChange(
      async (_event, session) => {
        state.session = session;

        if (session) {
          try {
            await loadUserData();
            showMainApp();
          } catch (error) {
            console.error(error);

            showAuthScreen();

            showToast(
              "Session error",
              error.message ||
                "Unable to load your account.",
              "error"
            );
          }
        } else {
          showAuthScreen();
        }
      }
    );

    if (state.session) {
      await loadUserData();
      showMainApp();
    } else {
      showAuthScreen();
    }

  } catch (error) {
    console.error("Initialization error:", error);

    showAuthScreen();

    showToast(
      "Application error",
      error.message ||
        "Could not initialize the application.",
      "error"
    );

  } finally {
    setLoading(false);
  }
}

document.addEventListener(
  "DOMContentLoaded",
  init
);