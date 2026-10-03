let sb = null;
let config = null;
let session = null;
let profile = null;
let files = [];
let trashFiles = [];
let clients = [];
let activity = [];
let selectedUpload = null;

const pageMeta = {
  dashboard:["Dashboard","Your private storage"],
  files:["My Files","Only your saved files"],
  upload:["Upload File","Add a new file to your private storage"],
  clients:["Clients","Organize files by client"],
  shared:["Shared Files","Manage your share links"],
  trash:["Trash","Restore or permanently delete files"],
  activity:["Activity","Your recent account activity"],
  settings:["Settings","Account information"],
  admin:["Admin Panel","Administrator controls"]
};

document.addEventListener("DOMContentLoaded", init);

async function init(){
  try{
    const r = await fetch("/api/config");
    config = await r.json();

    if(!config.supabaseUrl || !config.supabaseAnonKey){
      showToast("Server configuration is incomplete.");
      return;
    }

    sb = window.supabase.createClient(config.supabaseUrl, config.supabaseAnonKey, {
      auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}
    });

    sb.auth.onAuthStateChange(async (_event, newSession)=>{
      session = newSession;
      if(session) await loadApp();
      else showAuthScreen();
    });

    const {data} = await sb.auth.getSession();
    session = data.session;

    if(session) await loadApp();
    else showAuthScreen();

    document.getElementById("loginForm").addEventListener("submit", login);
    document.getElementById("registerForm").addEventListener("submit", register);
  }catch(e){
    console.error(e);
    showToast("Could not initialize the app.");
  }
}

function showAuthScreen(){
  document.getElementById("authScreen").classList.remove("hidden");
  document.getElementById("appShell").classList.add("hidden");
}

function showAuth(type){
  const login = type === "login";
  document.getElementById("loginForm").classList.toggle("hidden",!login);
  document.getElementById("registerForm").classList.toggle("hidden",login);
  document.getElementById("loginTab").classList.toggle("active",login);
  document.getElementById("registerTab").classList.toggle("active",!login);
}

async function api(path, options={}){
  const headers = new Headers(options.headers || {});
  if(session?.access_token) headers.set("Authorization",`Bearer ${session.access_token}`);
  if(options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")){
    headers.set("Content-Type","application/json");
  }
  const r = await fetch(path,{...options,headers});
  let data = {};
  try{ data = await r.json(); }catch{}
  if(!r.ok) throw new Error(data.error || "Request failed.");
  return data;
}

async function login(e){
  e.preventDefault();
  const identity = document.getElementById("loginIdentity").value.trim();
  const password = document.getElementById("loginPassword").value;

  try{
    const resolved = await api("/api/login-identity",{
      method:"POST",
      body:JSON.stringify({identity})
    });

    const {data,error} = await sb.auth.signInWithPassword({
      email:resolved.email,
      password
    });

    if(error) throw error;
    session = data.session;
    await loadApp();
  }catch(err){
    showToast(err.message || "Sign in failed.");
  }
}

async function register(e){
  e.preventDefault();

  const payload = {
    username:document.getElementById("regUsername").value.trim(),
    email:document.getElementById("regEmail").value.trim(),
    password:document.getElementById("regPassword").value,
    confirmPassword:document.getElementById("regConfirm").value,
    referralCode:document.getElementById("regReferral").value.trim()
  };

  try{
    const result = await api("/api/register",{
      method:"POST",
      body:JSON.stringify(payload)
    });

    showToast(result.message || "Account created.");
    document.getElementById("loginIdentity").value = payload.username;
    document.getElementById("loginPassword").value = "";
    document.getElementById("registerForm").reset();
    showAuth("login");
  }catch(err){
    showToast(err.message || "Registration failed.");
  }
}

async function loadApp(){
  try{
    const me = await api("/api/me");
    profile = me.profile;

    document.getElementById("authScreen").classList.add("hidden");
    document.getElementById("appShell").classList.remove("hidden");

    document.getElementById("topUsername").textContent = profile.username;
    document.getElementById("topRole").textContent = profile.role === "admin" ? "Administrator" : "User";
    document.getElementById("topAvatar").textContent = profile.username.charAt(0).toUpperCase();
    document.getElementById("adminNav").classList.toggle("hidden",profile.role !== "admin");

    await refreshData();
    navigate("dashboard");
  }catch(e){
    console.error(e);
    await logout();
  }
}

async function refreshData(){
  const results = await Promise.all([
    api("/api/files"),
    api("/api/trash"),
    api("/api/clients"),
    api("/api/activity")
  ]);
  files = results[0].files || [];
  trashFiles = results[1].files || [];
  clients = results[2].clients || [];
  activity = results[3].activity || [];
}

async function logout(){
  if(sb) await sb.auth.signOut();
  session = null;
  profile = null;
  document.getElementById("appShell").classList.add("hidden");
  showAuthScreen();
}

function navigate(page){
  if(page === "admin" && profile?.role !== "admin") return;

  document.querySelectorAll(".page").forEach(p=>p.classList.add("hidden"));
  const target = document.getElementById(`page-${page}`);
  if(target) target.classList.remove("hidden");

  document.querySelectorAll(".nav-item").forEach(n=>n.classList.toggle("active",n.dataset.page===page));

  document.getElementById("pageTitle").textContent = pageMeta[page]?.[0] || "Data Security";
  document.getElementById("pageSubtitle").textContent = pageMeta[page]?.[1] || "";

  document.getElementById("sidebar").classList.remove("open");

  if(page==="dashboard") renderDashboard();
  if(page==="files") renderFiles();
  if(page==="upload") renderUpload();
  if(page==="clients") renderClients();
  if(page==="shared") renderShared();
  if(page==="trash") renderTrash();
  if(page==="activity") renderActivity();
  if(page==="settings") renderSettings();
  if(page==="admin") renderAdmin();
}

function toggleSidebar(){
  document.getElementById("sidebar").classList.toggle("open");
}

function showToast(message){
  const t=document.getElementById("toast");
  t.textContent=message;
  t.classList.add("show");
  clearTimeout(window.toastTimer);
  window.toastTimer=setTimeout(()=>t.classList.remove("show"),2800);
}

function escapeHtml(v){
  return String(v ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
}

function formatBytes(bytes){
  if(!bytes) return "0 B";
  const units=["B","KB","MB","GB","TB"];
  const i=Math.min(Math.floor(Math.log(bytes)/Math.log(1024)),units.length-1);
  return `${(bytes/Math.pow(1024,i)).toFixed(i?2:0)} ${units[i]}`;
}

function fileIcon(file){
  const type=(file.mime_type||"").toLowerCase();
  if(type.startsWith("image/")) return "🖼️";
  if(type.startsWith("video/")) return "🎬";
  if(type.startsWith("audio/")) return "🎵";
  if(type.includes("pdf")) return "📕";
  if(type.includes("zip")||type.includes("rar")||type.includes("7z")) return "🗜️";
  if(type.includes("javascript")||type.includes("json")||type.includes("text")||/\.(cpp|c|java|py|html|css|js)$/i.test(file.original_name)) return "💻";
  return "📄";
}

function renderDashboard(){
  const used=files.reduce((sum,f)=>sum+Number(f.size||0),0);
  const el=document.getElementById("page-dashboard");

  el.innerHTML=`
    <div class="stats">
      <div class="stat"><div class="stat-head"><span>Total Files</span><div class="stat-icon">▣</div></div><h3>${files.length}</h3><p>Saved in your account</p></div>
      <div class="stat"><div class="stat-head"><span>Storage Used</span><div class="stat-icon">◈</div></div><h3>${formatBytes(used)}</h3><p>Actual uploaded data</p></div>
      <div class="stat"><div class="stat-head"><span>Shared Files</span><div class="stat-icon">↗</div></div><h3>0</h3><p>Share links you create</p></div>
      <div class="stat"><div class="stat-head"><span>Trash</span><div class="stat-icon">♲</div></div><h3>${trashFiles.length}</h3><p>Files in trash</p></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div><h3>Recent Files</h3><p>Only your real saved files appear here.</p></div><button class="secondary" onclick="navigate('files')">View All</button></div>
      ${files.length ? files.slice(0,5).map(fileRow).join("") : emptyState("▣","No files yet","Your dashboard is clean. Upload a file and it will appear here.","Upload File","navigate('upload')")}
    </div>`;
}

function emptyState(icon,title,text,buttonText,action){
  return `<div class="empty"><div class="empty-icon">${icon}</div><h3>${title}</h3><p>${text}</p>${buttonText?`<button class="secondary" onclick="${action}">${buttonText}</button>`:""}</div>`;
}

function fileRow(file,trash=false){
  return `<div class="file-row">
    <div class="file-name"><div class="file-icon">${fileIcon(file)}</div><div><b>${escapeHtml(file.original_name)}</b><small>${escapeHtml(file.mime_type)} • ${formatBytes(file.size)}</small></div></div>
    <small class="hide-mobile">${escapeHtml(file.category||"Other")}</small>
    <small class="hide-mobile">${new Date(file.created_at).toLocaleDateString()}</small>
    <div class="row-actions">
      ${trash
        ? `<button class="small-btn" onclick="restoreFile('${file.id}')">Restore</button><button class="small-btn optional" onclick="deleteFile('${file.id}')">Delete</button>`
        : `<button class="small-btn" onclick="downloadFile('${file.id}')">Download</button><button class="small-btn optional" onclick="shareFile('${file.id}')">Share</button><button class="small-btn optional" onclick="trashFile('${file.id}')">Delete</button>`}
    </div>
  </div>`;
}

function renderFiles(){
  const el=document.getElementById("page-files");
  el.innerHTML=`
    <div class="toolbar">
      <div class="search-wrap"><input class="search-input" id="fileSearch" placeholder="🔎 Search your saved files..." oninput="filterRenderedFiles()"></div>
      <select class="search-input" id="typeFilter" onchange="filterRenderedFiles()"><option value="all">All Types</option><option value="image">Images</option><option value="document">Documents</option><option value="code">Code</option><option value="video">Video</option></select>
      <button class="primary" style="width:auto;margin:0" onclick="navigate('upload')">+ Upload</button>
    </div>
    <div class="panel"><div class="panel-head"><div><h3>My Files</h3><p>${files.length} saved file${files.length===1?"":"s"}</p></div></div><div id="fileRows">${files.length?files.map(fileRow).join(""):emptyState("▣","No saved data","This area stays empty until you upload a file.","Upload File","navigate('upload')")}</div></div>`;
}

function filterRenderedFiles(){
  const q=(document.getElementById("fileSearch")?.value||"").toLowerCase();
  const type=document.getElementById("typeFilter")?.value||"all";
  document.querySelectorAll("#fileRows .file-row").forEach(row=>{
    const text=row.innerText.toLowerCase();
    let ok=text.includes(q);
    if(type!=="all"){
      const f=files.find(x=>row.innerText.includes(x.original_name));
      const mime=(f?.mime_type||"").toLowerCase();
      if(type==="image") ok=ok&&mime.startsWith("image/");
      if(type==="video") ok=ok&&mime.startsWith("video/");
      if(type==="document") ok=ok&&(mime.includes("pdf")||mime.includes("word")||mime.includes("document")||mime.includes("sheet"));
      if(type==="code") ok=ok&&(mime.includes("text")||/\.(cpp|c|java|py|html|css|js|json)$/i.test(f?.original_name||""));
    }
    row.style.display=ok?"grid":"none";
  });
}

function renderUpload(){
  const el=document.getElementById("page-upload");
  el.innerHTML=`
    <div class="panel" style="padding:20px">
      <div class="upload-area">
        <div class="big-icon">↑</div>
        <h2>Upload a file</h2>
        <p>Files are stored privately in Supabase Storage. Maximum: ${config.maxFileSizeMb} MB per file.</p>
        <label class="file-input-label">Choose File<input id="uploadInput" class="file-input" type="file" onchange="selectUpload(this)"></label>
        <div id="selectedUpload" class="muted" style="margin-top:15px"></div>
        <div class="progress"><div id="uploadProgress"></div></div>
      </div>
      <div class="form-grid">
        <div class="field full"><label>Description</label><textarea id="uploadDescription" placeholder="Optional description of this file"></textarea></div>
        <div class="field"><label>Client</label><select id="uploadClient"><option value="">No client</option>${clients.map(c=>`<option>${escapeHtml(c.name)}</option>`).join("")}</select></div>
        <div class="field"><label>Category</label><select id="uploadCategory"><option>Documents</option><option>Images</option><option>Videos</option><option>Code</option><option>Archives</option><option>Other</option></select></div>
        <div class="field full"><label>Tags</label><input id="uploadTags" placeholder="school, project, important"></div>
      </div>
      <button id="startUpload" class="primary" onclick="uploadSelected()" disabled>Upload File</button>
    </div>`;
}

function selectUpload(input){
  selectedUpload=input.files[0]||null;
  const out=document.getElementById("selectedUpload");
  const btn=document.getElementById("startUpload");
  if(!selectedUpload){
    out.textContent="";
    btn.disabled=true;
    return;
  }
  if(selectedUpload.size > config.maxFileSizeMb*1024*1024){
    out.textContent=`File is too large. Limit is ${config.maxFileSizeMb} MB.`;
    btn.disabled=true;
    return;
  }
  out.textContent=`✓ ${selectedUpload.name} • ${formatBytes(selectedUpload.size)}`;
  btn.disabled=false;
}

async function uploadSelected(){
  if(!selectedUpload) return;
  const btn=document.getElementById("startUpload");
  btn.disabled=true;
  const id=crypto.randomUUID();
  const clean=selectedUpload.name.replace(/[^a-zA-Z0-9._-]/g,"_").slice(0,120);
  const path=`${profile.id}/${id}-${clean}`;
  const progress=document.getElementById("uploadProgress");

  try{
    const {error:uploadError}=await sb.storage.from(config.storageBucket).upload(path,selectedUpload,{
      cacheControl:"3600",
      upsert:false,
      contentType:selectedUpload.type||"application/octet-stream"
    });
    if(uploadError) throw uploadError;
    progress.style.width="75%";

    const tags=document.getElementById("uploadTags").value.split(",").map(x=>x.trim()).filter(Boolean);
    const result=await api("/api/files/register",{
      method:"POST",
      body:JSON.stringify({
        id,
        originalName:selectedUpload.name,
        description:document.getElementById("uploadDescription").value,
        clientName:document.getElementById("uploadClient").value,
        category:document.getElementById("uploadCategory").value,
        tags,
        mimeType:selectedUpload.type||"application/octet-stream",
        size:selectedUpload.size
      })
    });

    progress.style.width="100%";
    showToast("File uploaded successfully.");
    selectedUpload=null;
    await refreshData();
    renderUpload();
    navigate("files");
  }catch(e){
    console.error(e);
    try{ await sb.storage.from(config.storageBucket).remove([path]); }catch{}
    showToast(e.message||"Upload failed.");
    btn.disabled=false;
  }
}

async function downloadFile(id){
  try{
    const data=await api(`/api/files/${id}/signed-url`,{method:"POST"});
    const a=document.createElement("a");
    a.href=data.url;
    a.target="_blank";
    a.rel="noopener";
    a.download=data.file.original_name;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }catch(e){showToast(e.message)}
}

async function trashFile(id){
  if(!confirm("Move this file to Trash?")) return;
  try{
    await api(`/api/files/${id}/trash`,{method:"POST"});
    await refreshData();
    renderFiles();
    showToast("File moved to Trash.");
  }catch(e){showToast(e.message)}
}

async function restoreFile(id){
  try{
    await api(`/api/files/${id}/restore`,{method:"POST"});
    await refreshData();
    renderTrash();
    showToast("File restored.");
  }catch(e){showToast(e.message)}
}

async function deleteFile(id){
  if(!confirm("Permanently delete this file? This cannot be undone.")) return;
  try{
    await api(`/api/files/${id}`,{method:"DELETE"});
    await refreshData();
    renderTrash();
    showToast("File permanently deleted.");
  }catch(e){showToast(e.message)}
}

async function shareFile(id){
  const expires=prompt("Expiration date/time (optional). Example: 2026-12-31T23:59:00");
  const password=prompt("Share password (optional). Leave blank for none.");
  const limit=prompt("Download limit (optional). Leave blank for unlimited.");

  try{
    const data=await api("/api/share",{
      method:"POST",
      body:JSON.stringify({
        fileId:id,
        expiresAt:expires||null,
        password:password||null,
        downloadLimit:limit||null
      })
    });
    openModal(`<h3>Secure Share Link</h3><p class="muted">Copy this link and share it with the intended recipient.</p><div class="share-url">${escapeHtml(data.url)}</div><button class="primary" onclick="navigator.clipboard.writeText('${data.url.replace(/'/g,"\\'")}');showToast('Link copied.');closeModal()">Copy Link</button>`);
    await refreshData();
  }catch(e){showToast(e.message)}
}

function renderClients(){
  const el=document.getElementById("page-clients");
  el.innerHTML=`
    <div class="toolbar"><button class="primary" style="width:auto;margin:0" onclick="addClient()">+ Add Client</button></div>
    <div class="panel">
      <div class="panel-head"><div><h3>Clients</h3><p>Your saved client groups</p></div></div>
      ${clients.length?`<div class="client-grid">${clients.map(c=>`<div class="client-card"><h4>${escapeHtml(c.name)}</h4><p>${escapeHtml(c.description||"No description")}</p></div>`).join("")}</div>`:emptyState("♙","No clients yet","Create a client to organize your files.","Add Client","addClient()")}
    </div>`;
}

async function addClient(){
  const name=prompt("Client name:");
  if(!name?.trim()) return;
  const description=prompt("Description (optional):")||"";
  try{
    await api("/api/clients",{method:"POST",body:JSON.stringify({name,description})});
    await refreshData();
    renderClients();
    showToast("Client created.");
  }catch(e){showToast(e.message)}
}

function renderShared(){
  document.getElementById("page-shared").innerHTML=`
    <div class="panel">${emptyState("↗","No shared files yet","When you create a share link for one of your files, it will be managed here.","My Files","navigate('files')")}</div>`;
}

function renderTrash(){
  document.getElementById("page-trash").innerHTML=`
    <div class="panel"><div class="panel-head"><div><h3>Trash</h3><p>Only files you deleted are shown here.</p></div></div>
    ${trashFiles.length?trashFiles.map(f=>fileRow(f,true)).join(""):emptyState("♲","Trash is empty","Deleted files will appear here.")}</div>`;
}

function renderActivity(){
  document.getElementById("page-activity").innerHTML=`
    <div class="panel"><div class="panel-head"><div><h3>Activity</h3><p>Your account activity</p></div></div>
    ${activity.length?activity.map(a=>`<div class="activity-item"><div class="activity-dot">•</div><div><b>${escapeHtml(a.action)}</b><small>${new Date(a.created_at).toLocaleString()}</small></div></div>`).join(""):emptyState("◷","No activity yet","Your activity log is empty.")}</div>`;
}

function renderSettings(){
  document.getElementById("page-settings").innerHTML=`
    <div class="panel"><div class="setting-box">
      <h3>Account</h3>
      <div class="form-grid">
        <div class="field"><label>Username</label><input value="${escapeHtml(profile.username)}" disabled></div>
        <div class="field"><label>Email</label><input value="${escapeHtml(profile.email)}" disabled></div>
        <div class="field"><label>Role</label><input value="${escapeHtml(profile.role)}" disabled></div>
        <div class="field"><label>Account Status</label><input value="${profile.disabled?"Disabled":"Active"}" disabled></div>
      </div>
    </div></div>
    <div class="panel"><div class="setting-box"><h3>About Data Security</h3><p class="muted">Data Security is a private file storage and management platform designed to help users securely organize, access, download, and optionally share their files.</p></div></div>`;
}

async function renderAdmin(){
  if(profile?.role!=="admin") return;
  try{
    const data=await api("/api/admin/data");
    const users=data.users||[];
    const totalStorage=(data.files||[]).reduce((s,f)=>s+Number(f.size||0),0);

    document.getElementById("page-admin").innerHTML=`
      <div class="stats">
        <div class="stat"><div class="stat-head"><span>Users</span><div class="stat-icon">♙</div></div><h3>${users.length}</h3><p>Registered accounts</p></div>
        <div class="stat"><div class="stat-head"><span>Files</span><div class="stat-icon">▣</div></div><h3>${data.files.length}</h3><p>All user files</p></div>
        <div class="stat"><div class="stat-head"><span>Storage</span><div class="stat-icon">◈</div></div><h3>${formatBytes(totalStorage)}</h3><p>Total stored data</p></div>
        <div class="stat"><div class="stat-head"><span>Admins</span><div class="stat-icon">♛</div></div><h3>${users.filter(u=>u.role==="admin").length}</h3><p>Administrator accounts</p></div>
      </div>
      <div class="panel"><div class="panel-head"><div><h3>Users</h3><p>Server-authorized user management</p></div></div>
      <div style="overflow:auto"><table class="admin-table"><thead><tr><th>User</th><th>Role</th><th>Files</th><th>Storage</th><th>Status</th><th>Action</th></tr></thead><tbody>
      ${users.map(u=>{
        const count=data.files.filter(f=>f.owner_id===u.id).length;
        const storage=data.storageByUser[u.id]||0;
        return `<tr><td><b>${escapeHtml(u.username)}</b><br><span class="muted">${escapeHtml(u.email)}</span></td><td>${escapeHtml(u.role)}</td><td>${count}</td><td>${formatBytes(storage)}</td><td><span class="status ${u.disabled?"off":""}">${u.disabled?"Disabled":"Active"}</span></td><td>${u.id===profile.id?"Current Admin":`<button class="small-btn" onclick="toggleUser('${u.id}',${!u.disabled})">${u.disabled?"Enable":"Disable"}</button> <button class="small-btn" onclick="deleteUser('${u.id}')">Delete</button>`}</td></tr>`;
      }).join("")}
      </tbody></table></div></div>`;
  }catch(e){showToast(e.message)}
}

async function toggleUser(id,disabled){
  try{
    await api(`/api/admin/user/${id}/disable`,{method:"POST",body:JSON.stringify({disabled})});
    renderAdmin();
    showToast(disabled?"User disabled.":"User enabled.");
  }catch(e){showToast(e.message)}
}

async function deleteUser(id){
  if(!confirm("Delete this user and their stored files permanently?")) return;
  try{
    await api(`/api/admin/user/${id}`,{method:"DELETE"});
    renderAdmin();
    showToast("User deleted.");
  }catch(e){showToast(e.message)}
}

function openModal(html){
  document.getElementById("modalContent").innerHTML=html;
  document.getElementById("modal").classList.remove("hidden");
}
function closeModal(){
  document.getElementById("modal").classList.add("hidden");
  document.getElementById("modalContent").innerHTML="";
}
