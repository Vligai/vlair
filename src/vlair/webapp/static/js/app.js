/**
 * vlair — Security Operations Platform
 * Vue 3 SPA (CDN / no build step)
 */
import { createApp, ref, reactive, computed, onMounted, watch, nextTick } from "vue";
import { createRouter, createWebHistory } from "vue-router";

// ─────────────────────────────────────────────────────────────────────────────
// Auth store (simple reactive singleton)
// ─────────────────────────────────────────────────────────────────────────────
const auth = reactive({
  user: null,
  accessToken: localStorage.getItem("access_token") || null,
  refreshToken: localStorage.getItem("refresh_token") || null,
  get isLoggedIn() { return !!this.accessToken && !!this.user; },
  get role() { return this.user?.role || ""; },
});

function setTokens(access, refresh) {
  auth.accessToken = access;
  auth.refreshToken = refresh;
  localStorage.setItem("access_token", access);
  if (refresh) localStorage.setItem("refresh_token", refresh);
}

function clearAuth() {
  auth.user = null;
  auth.accessToken = null;
  auth.refreshToken = null;
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

// ─────────────────────────────────────────────────────────────────────────────
// API helper
// ─────────────────────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (auth.accessToken) headers["Authorization"] = `Bearer ${auth.accessToken}`;

  // Support multipart (file uploads) — skip Content-Type so browser sets boundary
  if (opts.body instanceof FormData) delete headers["Content-Type"];

  const res = await fetch(path, { ...opts, headers });

  // Auto-refresh on 401
  if (res.status === 401 && auth.refreshToken && !path.includes("/api/auth/refresh")) {
    const ok = await tryRefresh();
    if (ok) {
      headers["Authorization"] = `Bearer ${auth.accessToken}`;
      return fetch(path, { ...opts, headers });
    }
    clearAuth();
    router.push("/login");
    return res;
  }

  return res;
}

async function tryRefresh() {
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: auth.refreshToken }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    auth.accessToken = data.access_token;
    localStorage.setItem("access_token", data.access_token);
    return true;
  } catch { return false; }
}

async function fetchMe() {
  try {
    const res = await apiFetch("/api/auth/me");
    if (res.ok) { const d = await res.json(); auth.user = d.user; }
    else { clearAuth(); }
  } catch { clearAuth(); }
}

async function copyText(text) {
  if (text) await navigator.clipboard.writeText(text);
}

// ─────────────────────────────────────────────────────────────────────────────
// Views
// ─────────────────────────────────────────────────────────────────────────────

// ── Login / Register ──────────────────────────────────────────────────────────
const LoginView = {
  template: `
  <div class="auth-wrap">
    <div class="auth-box">
      <div class="auth-logo">vlair</div>
      <div class="auth-subtitle">Security Operations Platform</div>

      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-if="success" class="alert alert-success">{{ success }}</div>

      <form @submit.prevent="mode==='login' ? doLogin() : doRegister()">
        <div v-if="mode==='register'" class="form-group">
          <label class="form-label">Email</label>
          <input v-model="email" type="email" class="form-control" placeholder="analyst@example.com" required />
        </div>
        <div class="form-group">
          <label class="form-label">Username</label>
          <input v-model="username" type="text" class="form-control" placeholder="username" autocomplete="username" required />
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input v-model="password" type="password" class="form-control" placeholder="••••••••" autocomplete="current-password" required />
        </div>
        <div v-if="needsMfa" class="form-group">
          <label class="form-label">TOTP Code</label>
          <input v-model="totpCode" type="text" class="form-control" placeholder="6-digit code" maxlength="6" />
        </div>
        <button type="submit" class="btn btn-primary btn-full" :disabled="loading">
          <span v-if="loading" class="spinner"></span>
          {{ mode==='login' ? 'Sign In' : 'Create Account' }}
        </button>
      </form>

      <div class="auth-toggle">
        <span v-if="mode==='login'">Don't have an account? <a href="#" @click.prevent="switchMode('register')">Register</a></span>
        <span v-else>Already have an account? <a href="#" @click.prevent="switchMode('login')">Sign In</a></span>
      </div>
    </div>
  </div>`,
  setup() {
    const mode = ref("login");
    const username = ref(""); const email = ref(""); const password = ref("");
    const totpCode = ref(""); const needsMfa = ref(false);
    const loading = ref(false); const error = ref(""); const success = ref("");

    function switchMode(m) {
      mode.value = m; error.value = ""; success.value = "";
      username.value = ""; email.value = ""; password.value = ""; totpCode.value = "";
      needsMfa.value = false;
    }

    async function doLogin() {
      loading.value = true; error.value = "";
      try {
        const body = { username: username.value, password: password.value };
        if (needsMfa.value) body.totp_code = totpCode.value;
        const res = await fetch("/api/auth/login", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.mfa_required) { needsMfa.value = true; loading.value = false; return; }
        if (!res.ok) { error.value = data.error || "Login failed"; loading.value = false; return; }
        setTokens(data.access_token, data.refresh_token);
        auth.user = data.user;
        router.push("/dashboard");
      } catch (e) { error.value = "Network error"; }
      loading.value = false;
    }

    async function doRegister() {
      loading.value = true; error.value = "";
      try {
        const res = await fetch("/api/auth/register", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username.value, email: email.value, password: password.value }),
        });
        const data = await res.json();
        if (!res.ok) { error.value = data.error || "Registration failed"; loading.value = false; return; }
        success.value = "Account created! Please sign in.";
        switchMode("login");
      } catch (e) { error.value = "Network error"; }
      loading.value = false;
    }

    return { mode, username, email, password, totpCode, needsMfa, loading, error, success, doLogin, doRegister, switchMode };
  },
};

// ── Dashboard ─────────────────────────────────────────────────────────────────
const DashboardView = {
  template: `
  <div>
    <div class="page-title">📊 Dashboard</div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{{ stats.tools }}</div>
        <div class="stat-label">Available Tools</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ stats.role }}</div>
        <div class="stat-label">Your Role</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ stats.status }}</div>
        <div class="stat-label">API Status</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ stats.version }}</div>
        <div class="stat-label">Version</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">🚀 Quick Actions</div>
      <div class="tool-grid">
        <div v-for="t in quickTools" :key="t.path" class="tool-card" @click="$router.push('/tools/' + t.id)">
          <div class="tool-card-icon">{{ t.icon }}</div>
          <div class="tool-card-name">{{ t.name }}</div>
          <div class="tool-card-desc">{{ t.desc }}</div>
          <div class="tool-card-role"><span :class="'pill pill-' + t.role">{{ t.role }}</span></div>
        </div>
      </div>
    </div>

    <div class="card" v-if="health">
      <div class="card-title">💚 System Health</div>
      <table>
        <tr><td class="text-muted" style="width:160px">Status</td><td><span class="pill pill-success">{{ health.status }}</span></td></tr>
        <tr><td class="text-muted">API Version</td><td>{{ health.version }}</td></tr>
        <tr><td class="text-muted">Timestamp</td><td class="text-mono">{{ health.timestamp }}</td></tr>
      </table>
    </div>
  </div>`,
  setup() {
    const stats = reactive({ tools: 13, role: auth.user?.role || "—", status: "—", version: "—" });
    const health = ref(null);
    const quickTools = [
      { id: "ioc",    name: "IOC Extractor",    icon: "🔍", desc: "Extract IPs, domains, hashes from text",   role: "analyst" },
      { id: "hash",   name: "Hash Lookup",      icon: "🔐", desc: "Threat intelligence for file hashes",      role: "analyst" },
      { id: "intel",  name: "Domain/IP Intel",  icon: "🌐", desc: "DNS & threat intel for domains and IPs",   role: "analyst" },
      { id: "url",    name: "URL Analyzer",     icon: "🔗", desc: "Check URLs against threat databases",      role: "analyst" },
      { id: "eml",    name: "Email Parser",     icon: "📧", desc: "Analyze phishing and suspicious emails",   role: "analyst" },
      { id: "deobfus", name: "Deobfuscator",     icon: "🔓", desc: "Deobfuscate PowerShell/JS malware",        role: "analyst" },
    ];
    onMounted(async () => {
      const res = await fetch("/api/health");
      if (res.ok) {
        health.value = await res.json();
        stats.status = health.value.status === "healthy" ? "OK" : "Down";
        stats.version = health.value.version;
      }
      stats.role = auth.user?.role || "—";
    });
    return { stats, health, quickTools };
  },
};

// ── Tools ─────────────────────────────────────────────────────────────────────
const ALL_TOOLS = [
  { id: "ioc",       name: "IOC Extractor",      icon: "🔍", role: "analyst",        desc: "Extract IPs, domains, URLs, hashes, CVEs from free text or files." },
  { id: "hash",      name: "Hash Lookup",         icon: "🔐", role: "analyst",        desc: "Query VirusTotal and MalwareBazaar for file hash threat intelligence." },
  { id: "intel",     name: "Domain/IP Intel",     icon: "🌐", role: "analyst",        desc: "DNS resolution, reverse lookup, and threat reputation for domains/IPs." },
  { id: "url",       name: "URL Analyzer",        icon: "🔗", role: "analyst",        desc: "Analyze URLs against VirusTotal, URLhaus, and 11 heuristic checks." },
  { id: "log",       name: "Log Analyzer",        icon: "📋", role: "analyst",        desc: "Detect attacks, brute-force, and scanners in Apache/Nginx/syslog files." },
  { id: "eml",       name: "Email Parser",        icon: "📧", role: "analyst",        desc: "Parse EML files: headers, SPF/DKIM/DMARC, attachments, embedded URLs." },
  { id: "yara",      name: "YARA Scanner",        icon: "🛡️", role: "analyst",        desc: "Scan files against YARA rules with severity classification." },
  { id: "cert",      name: "Cert Analyzer",       icon: "🔑", role: "analyst",        desc: "Inspect SSL/TLS certificates for expiry, weak crypto, phishing patterns." },
  { id: "deobfus",   name: "Deobfuscator",        icon: "🔓", role: "analyst",        desc: "Decode PowerShell, JavaScript, VBScript and other obfuscated scripts." },
  { id: "pcap",      name: "PCAP Analyzer",       icon: "📡", role: "analyst",        desc: "Analyze network captures: protocols, port scans, DNS threats, HTTP." },
  { id: "threatfeed",name: "Threat Feed Search",  icon: "📰", role: "analyst",        desc: "Search ThreatFox and URLhaus IOC database." },
  { id: "feedupdate",name: "Threat Feed Update",  icon: "🔄", role: "senior_analyst", desc: "Pull fresh IOC data from threat feed sources (requires senior analyst)." },
  { id: "carve",     name: "File Carver",         icon: "🗂️", role: "senior_analyst", desc: "Extract embedded files from disk images or memory dumps." },
];

const ToolsListView = {
  template: `
  <div>
    <div class="page-title">🛠️ Security Tools</div>
    <div class="tool-grid">
      <div v-for="t in tools" :key="t.id" class="tool-card" @click="$router.push('/tools/' + t.id)">
        <div class="tool-card-icon">{{ t.icon }}</div>
        <div class="tool-card-name">{{ t.name }}</div>
        <div class="tool-card-desc">{{ t.desc }}</div>
        <div class="tool-card-role"><span :class="'pill pill-' + t.role.replace('_','-')">{{ t.role }}</span></div>
      </div>
    </div>
  </div>`,
  setup() { return { tools: ALL_TOOLS }; },
};

// ── Individual tool panel ─────────────────────────────────────────────────────
const ToolView = {
  template: `
  <div>
    <div class="page-title">
      <span>{{ tool?.icon }}</span> {{ tool?.name }}
      <a href="#" @click.prevent="$router.push('/tools')" style="font-size:13px;margin-left:auto" class="text-muted">← All Tools</a>
    </div>
    <div v-if="!tool" class="alert alert-error">Tool not found.</div>
    <template v-else>
      <!-- IOC Extractor -->
      <template v-if="toolId==='ioc'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Paste text or upload file</label>
            <textarea v-model="iocText" class="form-control" placeholder="Paste report, email body, log snippet..."></textarea>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <label class="btn btn-secondary btn-sm" style="cursor:pointer">
              📎 Upload File
              <input type="file" style="display:none" @change="onFileChange($event,'ioc')" />
            </label>
            <span class="text-muted" style="font-size:12px">{{ fileName || '' }}</span>
            <button class="btn btn-primary" :disabled="running" @click="runIoc">
              <span v-if="running" class="spinner"></span> Extract IOCs
            </button>
          </div>
        </div>
      </template>

      <!-- Hash Lookup -->
      <template v-else-if="toolId==='hash'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Hashes (one per line — MD5, SHA1, SHA256)</label>
            <textarea v-model="hashText" class="form-control" placeholder="44d88612fea8a8f36de82e1278abb02f&#10;..."></textarea>
          </div>
          <button class="btn btn-primary" :disabled="running" @click="runHash">
            <span v-if="running" class="spinner"></span> Lookup Hashes
          </button>
        </div>
      </template>

      <!-- Domain/IP Intel -->
      <template v-else-if="toolId==='intel'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Domains or IPs (one per line)</label>
            <textarea v-model="intelTarget" class="form-control" placeholder="example.com&#10;1.2.3.4&#10;..."></textarea>
          </div>
          <button class="btn btn-primary" :disabled="running" @click="runIntel">
            <span v-if="running" class="spinner"></span> Analyze
          </button>
        </div>
      </template>

      <!-- URL Analyzer -->
      <template v-else-if="toolId==='url'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">URLs to analyze (one per line)</label>
            <textarea v-model="urlText" class="form-control" placeholder="https://malicious.example.com/path&#10;..."></textarea>
          </div>
          <button class="btn btn-primary" :disabled="running" @click="runUrl">
            <span v-if="running" class="spinner"></span> Analyze URLs
          </button>
        </div>
      </template>

      <!-- Log Analyzer -->
      <template v-else-if="toolId==='log'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Upload log file (.log / .txt)</label>
            <label class="btn btn-secondary" style="cursor:pointer">
              📎 Choose Log File
              <input type="file" style="display:none" accept=".log,.txt" @change="onFileChange($event,'log')" />
            </label>
            <span class="text-muted" style="font-size:12px;margin-left:8px">{{ fileName || 'No file selected' }}</span>
          </div>
          <div class="form-group">
            <label class="form-label">Log format</label>
            <select v-model="logFormat" class="form-control">
              <option value="auto">Auto-detect</option>
              <option value="apache">Apache/Nginx access</option>
              <option value="syslog">Syslog</option>
            </select>
          </div>
          <button class="btn btn-primary" :disabled="running || !uploadedFile" @click="runLog">
            <span v-if="running" class="spinner"></span> Analyze Log
          </button>
        </div>
      </template>

      <!-- Email Parser -->
      <template v-else-if="toolId==='eml'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Upload .eml file</label>
            <label class="btn btn-secondary" style="cursor:pointer">
              📎 Choose EML File
              <input type="file" style="display:none" accept=".eml,.msg" @change="onFileChange($event,'eml')" />
            </label>
            <span class="text-muted" style="font-size:12px;margin-left:8px">{{ fileName || 'No file selected' }}</span>
          </div>
          <button class="btn btn-primary" :disabled="running || !uploadedFile" @click="runEml">
            <span v-if="running" class="spinner"></span> Parse Email
          </button>
        </div>
      </template>

      <!-- YARA Scanner -->
      <template v-else-if="toolId==='yara'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">File to scan</label>
            <label class="btn btn-secondary" style="cursor:pointer">
              📎 Choose File
              <input type="file" style="display:none" @change="onFileChange($event,'sample')" />
            </label>
            <span class="text-muted" style="font-size:12px;margin-left:8px">{{ fileName || 'No file selected' }}</span>
          </div>
          <div class="form-group">
            <label class="form-label">YARA rules (paste rules text)</label>
            <textarea v-model="yaraRules" class="form-control" placeholder="rule ExampleRule { strings: $s = &quot;malware&quot; condition: $s }"></textarea>
          </div>
          <button class="btn btn-primary" :disabled="running || !uploadedFile" @click="runYara">
            <span v-if="running" class="spinner"></span> Scan File
          </button>
        </div>
      </template>

      <!-- Cert Analyzer -->
      <template v-else-if="toolId==='cert'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Hostname or IP</label>
            <input v-model="certHost" class="form-control" placeholder="example.com" />
          </div>
          <div class="form-group">
            <label class="form-label">Port (default 443)</label>
            <input v-model.number="certPort" type="number" class="form-control" value="443" min="1" max="65535" />
          </div>
          <button class="btn btn-primary" :disabled="running || !certHost" @click="runCert">
            <span v-if="running" class="spinner"></span> Analyze Certificate
          </button>
        </div>
      </template>

      <!-- Deobfuscator -->
      <template v-else-if="toolId==='deobfus'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Language</label>
            <select v-model="deobLang" class="form-control">
              <option value="auto">Auto-detect</option>
              <option value="powershell">PowerShell</option>
              <option value="javascript">JavaScript</option>
              <option value="vbscript">VBScript</option>
              <option value="batch">Batch</option>
              <option value="python">Python</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Paste obfuscated code</label>
            <textarea v-model="deobCode" class="form-control" placeholder="Paste obfuscated script here..."></textarea>
          </div>
          <button class="btn btn-primary" :disabled="running || !deobCode" @click="runDeobfus">
            <span v-if="running" class="spinner"></span> Deobfuscate
          </button>
        </div>
      </template>

      <!-- PCAP Analyzer -->
      <template v-else-if="toolId==='pcap'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Upload PCAP file (.pcap / .pcapng)</label>
            <label class="btn btn-secondary" style="cursor:pointer">
              📎 Choose PCAP File
              <input type="file" style="display:none" accept=".pcap,.pcapng,.cap" @change="onFileChange($event,'pcap')" />
            </label>
            <span class="text-muted" style="font-size:12px;margin-left:8px">{{ fileName || 'No file selected' }}</span>
          </div>
          <button class="btn btn-primary" :disabled="running || !uploadedFile" @click="runPcap">
            <span v-if="running" class="spinner"></span> Analyze PCAP
          </button>
        </div>
      </template>

      <!-- Threat Feed Search -->
      <template v-else-if="toolId==='threatfeed'">
        <div class="card">
          <div class="card-title">Search Threat Feeds</div>
          <div class="form-group">
            <label class="form-label">Search term (IOC value, malware family…)</label>
            <input v-model="feedQuery" class="form-control" placeholder="e.g. cobalt strike, 1.2.3.4" />
          </div>
          <button class="btn btn-primary" :disabled="running || !feedQuery" @click="runFeedSearch">
            <span v-if="running" class="spinner"></span> Search
          </button>
        </div>
      </template>

      <!-- Threat Feed Update -->
      <template v-else-if="toolId==='feedupdate'">
        <div class="card">
          <div class="card-title">Update Threat Feeds</div>
          <p class="text-muted mb-16" style="font-size:13px">Pull fresh IOC data from ThreatFox and URLhaus. This may take 30–60 seconds.</p>
          <button class="btn btn-primary" :disabled="running" @click="runFeedUpdate">
            <span v-if="running" class="spinner"></span> Update All Feeds
          </button>
        </div>
      </template>

      <!-- File Carver -->
      <template v-else-if="toolId==='carve'">
        <div class="card">
          <div class="card-title">Input</div>
          <div class="form-group">
            <label class="form-label">Upload disk image or memory dump</label>
            <label class="btn btn-secondary" style="cursor:pointer">
              📎 Choose Image File
              <input type="file" style="display:none" accept=".bin,.img,.raw,.dd,.exe,.dll" @change="onFileChange($event,'binary')" />
            </label>
            <span class="text-muted" style="font-size:12px;margin-left:8px">{{ fileName || 'No file selected' }}</span>
          </div>
          <button class="btn btn-primary" :disabled="running || !uploadedFile" @click="runCarve">
            <span v-if="running" class="spinner"></span> Carve Files
          </button>
        </div>
      </template>

      <!-- Error / result -->
      <div v-if="error" class="alert alert-error">{{ error }}</div>

      <template v-if="result">

        <!-- Hash Lookup Results -->
        <template v-if="toolId==='hash'">
          <div class="card">
            <div class="card-title">Summary</div>
            <div class="stats-grid">
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.total }}</div><div class="stat-label">Hashes</div></div>
              <div class="stat-card stat-card-sm stat-malicious"><div class="stat-value">{{ result.statistics?.verdicts?.malicious }}</div><div class="stat-label">Malicious</div></div>
              <div class="stat-card stat-card-sm stat-suspicious"><div class="stat-value">{{ result.statistics?.verdicts?.suspicious }}</div><div class="stat-label">Suspicious</div></div>
              <div class="stat-card stat-card-sm stat-clean"><div class="stat-value">{{ result.statistics?.verdicts?.clean }}</div><div class="stat-label">Clean</div></div>
            </div>
            <div class="chart-container"><canvas ref="hashChartCanvas"></canvas></div>
          </div>
          <div class="card" v-for="r in result.results" :key="r.hash">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
              <span class="text-mono" style="font-size:12px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis">{{ r.hash }}</span>
              <span :class="'verdict-badge verdict-' + r.verdict">{{ r.verdict }}</span>
              <span class="risk-number" :style="riskColor(r.risk_score)">{{ r.risk_score }}</span>
            </div>
            <div class="text-muted" style="font-size:12px;margin-top:6px">Type: {{ r.type }}</div>
          </div>
        </template>

        <!-- IOC Extractor Results -->
        <template v-else-if="toolId==='ioc'">
          <div class="card">
            <div class="card-title">Summary — {{ result.statistics?.total_iocs }} IOCs</div>
            <div class="chart-container"><canvas ref="iocChartCanvas"></canvas></div>
          </div>
          <div class="card" v-if="result.results?.ips?.length">
            <div class="card-title">IP Addresses ({{ result.results.ips.length }})</div>
            <div class="ioc-list">
              <span class="ioc-pill" v-for="ip in result.results.ips" :key="ip">{{ ip }}</span>
            </div>
          </div>
          <div class="card" v-if="result.results?.domains?.length">
            <div class="card-title">Domains ({{ result.results.domains.length }})</div>
            <div class="ioc-list">
              <span class="ioc-pill" v-for="d in result.results.domains" :key="d">{{ d }}</span>
            </div>
          </div>
          <div class="card" v-if="result.results?.urls?.length">
            <div class="card-title">URLs ({{ result.results.urls.length }})</div>
            <div class="ioc-list">
              <span class="ioc-pill ioc-pill-url" v-for="u in result.results.urls" :key="u">{{ u }}</span>
            </div>
          </div>
          <div class="card" v-if="result.results?.emails?.length">
            <div class="card-title">Emails ({{ result.results.emails.length }})</div>
            <div class="ioc-list">
              <span class="ioc-pill" v-for="e in result.results.emails" :key="e">{{ e }}</span>
            </div>
          </div>
          <div class="card" v-if="allHashes.length">
            <div class="card-title">Hashes ({{ allHashes.length }})</div>
            <div class="table-wrap">
              <table><thead><tr><th>Hash</th><th>Type</th></tr></thead>
              <tbody><tr v-for="h in allHashes" :key="h.value"><td class="text-mono" style="font-size:11px">{{ h.value }}</td><td>{{ h.type }}</td></tr></tbody></table>
            </div>
          </div>
          <div class="card" v-if="result.results?.cves?.length">
            <div class="card-title">CVEs ({{ result.results.cves.length }})</div>
            <div class="ioc-list">
              <span class="ioc-pill" v-for="c in result.results.cves" :key="c">{{ c }}</span>
            </div>
          </div>
        </template>

        <!-- Domain/IP Intel Results -->
        <template v-else-if="toolId==='intel'">
          <div class="card" v-for="r in result.results" :key="r.target">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px">
              <span class="text-mono">{{ r.target }}</span>
              <span class="pill">{{ r.type }}</span>
              <span :class="'verdict-badge verdict-' + r.classification">{{ r.classification }}</span>
              <span class="risk-number" :style="riskColor(r.risk_score)">{{ r.risk_score }}</span>
            </div>
            <div v-if="r.dns_records" class="text-muted" style="font-size:12px">
              DNS: {{ formatDns(r.dns_records) }}
            </div>
          </div>
        </template>

        <!-- URL Analyzer Results -->
        <template v-else-if="toolId==='url'">
          <div class="card" v-for="r in result.results" :key="r.url">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px">
              <span class="text-mono" style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.url }}</span>
              <span :class="'verdict-badge verdict-' + r.verdict">{{ r.verdict }}</span>
              <span class="risk-number" :style="riskColor(r.risk_score)">{{ r.risk_score }}</span>
            </div>
            <div class="ioc-list" v-if="triggeredChecks(r).length">
              <span class="sev-badge sev-medium" v-for="c in triggeredChecks(r)" :key="c">&#9888; {{ c }}</span>
            </div>
          </div>
        </template>

        <!-- Log Analyzer Results -->
        <template v-else-if="toolId==='log'">
          <div class="card">
            <div class="card-title">Summary</div>
            <div class="stats-grid">
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.total_lines }}</div><div class="stat-label">Log Lines</div></div>
              <div class="stat-card stat-card-sm stat-malicious"><div class="stat-value">{{ result.statistics?.attacks_detected }}</div><div class="stat-label">Attacks</div></div>
            </div>
          </div>
          <div class="card" v-if="result.alerts?.length">
            <div class="card-title">Alerts</div>
            <div class="table-wrap">
              <table><thead><tr><th>Type</th><th>Severity</th><th>Count</th></tr></thead>
              <tbody>
                <tr v-for="a in result.alerts" :key="a.type">
                  <td>{{ a.type }}</td>
                  <td><span :class="'sev-badge sev-' + a.severity">{{ a.severity }}</span></td>
                  <td>{{ a.count }}</td>
                </tr>
              </tbody></table>
            </div>
          </div>
          <div class="card" v-if="result.top_ips?.length">
            <div class="card-title">Top Source IPs</div>
            <div class="table-wrap">
              <table><thead><tr><th>IP</th><th>Requests</th></tr></thead>
              <tbody><tr v-for="ip in result.top_ips" :key="ip.ip"><td class="text-mono">{{ ip.ip }}</td><td>{{ ip.count }}</td></tr></tbody></table>
            </div>
          </div>
        </template>

        <!-- Email Parser Results -->
        <template v-else-if="toolId==='eml'">
          <div class="card">
            <div class="card-title">Headers</div>
            <table>
              <tr><td class="text-muted" style="width:100px">From</td><td>{{ result.results?.headers?.from }}</td></tr>
              <tr><td class="text-muted">Subject</td><td>{{ result.results?.headers?.subject }}</td></tr>
              <tr><td class="text-muted">Date</td><td>{{ result.results?.headers?.date }}</td></tr>
              <tr><td class="text-muted">SPF</td><td><span :class="authBadge(result.results?.headers?.spf)">{{ result.results?.headers?.spf }}</span></td></tr>
              <tr><td class="text-muted">DKIM</td><td><span :class="authBadge(result.results?.headers?.dkim)">{{ result.results?.headers?.dkim }}</span></td></tr>
              <tr><td class="text-muted">DMARC</td><td><span :class="authBadge(result.results?.headers?.dmarc)">{{ result.results?.headers?.dmarc }}</span></td></tr>
            </table>
          </div>
          <div class="card" v-if="result.results?.attachments?.length">
            <div class="card-title">Attachments ({{ result.results.attachments.length }})</div>
            <div class="table-wrap">
              <table><thead><tr><th>Filename</th><th>Size</th><th>SHA256</th></tr></thead>
              <tbody>
                <tr v-for="a in result.results.attachments" :key="a.filename">
                  <td>{{ a.filename }}</td>
                  <td>{{ formatSize(a.size) }}</td>
                  <td class="text-mono" style="font-size:10px">{{ a.hashes?.sha256?.slice(0,16) }}&#8230;</td>
                </tr>
              </tbody></table>
            </div>
          </div>
          <div class="card" v-if="result.results?.embedded_urls?.length">
            <div class="card-title">Embedded URLs ({{ result.results.embedded_urls.length }})</div>
            <div class="ioc-list">
              <span class="ioc-pill ioc-pill-url" v-for="u in result.results.embedded_urls" :key="u">{{ u }}</span>
            </div>
          </div>
        </template>

        <!-- PCAP Analyzer Results -->
        <template v-else-if="toolId==='pcap'">
          <div class="card">
            <div class="card-title">Summary</div>
            <div class="stats-grid">
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.total_packets?.toLocaleString() }}</div><div class="stat-label">Packets</div></div>
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ formatSize(result.statistics?.total_bytes) }}</div><div class="stat-label">Total Size</div></div>
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.capture_duration_seconds?.toFixed(1) }}s</div><div class="stat-label">Duration</div></div>
            </div>
            <div class="chart-container"><canvas ref="pcapChartCanvas"></canvas></div>
          </div>
          <div class="card" v-if="result.alerts?.length">
            <div class="card-title">Alerts</div>
            <div class="table-wrap">
              <table><thead><tr><th>Type</th><th>Severity</th><th>Description</th></tr></thead>
              <tbody>
                <tr v-for="a in result.alerts" :key="a.type + a.description">
                  <td>{{ a.type }}</td>
                  <td><span :class="'sev-badge sev-' + a.severity">{{ a.severity }}</span></td>
                  <td style="font-size:12px">{{ a.description }}</td>
                </tr>
              </tbody></table>
            </div>
          </div>
          <div class="card" v-if="result.top_talkers?.length">
            <div class="card-title">Top Talkers</div>
            <div class="table-wrap">
              <table><thead><tr><th>Source</th><th>Dest</th><th>Proto</th><th>Packets</th></tr></thead>
              <tbody>
                <tr v-for="t in result.top_talkers.slice(0,10)" :key="t.source_ip+t.dest_ip">
                  <td class="text-mono">{{ t.source_ip }}</td>
                  <td class="text-mono">{{ t.dest_ip }}</td>
                  <td>{{ t.protocol }}</td>
                  <td>{{ t.packets }}</td>
                </tr>
              </tbody></table>
            </div>
          </div>
        </template>

        <!-- Cert Analyzer Results -->
        <template v-else-if="toolId==='cert'">
          <div class="card">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
              <span :class="'verdict-badge verdict-' + result.results?.verdict">{{ result.results?.verdict }}</span>
              <span class="risk-number" :style="riskColor(result.results?.risk_score)">{{ result.results?.risk_score }}</span>
            </div>
            <table>
              <tr><td class="text-muted" style="width:130px">Subject CN</td><td>{{ result.results?.subject?.common_name }}</td></tr>
              <tr><td class="text-muted">Issuer</td><td>{{ result.results?.issuer?.organization }}</td></tr>
              <tr><td class="text-muted">Valid Until</td><td>{{ result.results?.validity?.not_after?.slice(0,10) }}
                <span v-if="result.results?.validity?.is_expired" class="sev-badge sev-critical">EXPIRED</span>
                <span v-else class="text-muted" style="font-size:11px"> ({{ result.results?.validity?.days_remaining }}d left)</span>
              </td></tr>
              <tr><td class="text-muted">Key</td><td>{{ result.results?.key_info?.algorithm }} {{ result.results?.key_info?.key_size }}b
                <span v-if="result.results?.key_info?.is_weak" class="sev-badge sev-high">WEAK</span>
              </td></tr>
            </table>
          </div>
          <div class="card" v-if="result.results?.security_issues?.length">
            <div class="card-title">Security Issues</div>
            <div v-for="i in result.results.security_issues" :key="i.type" style="margin-bottom:6px">
              <span :class="'sev-badge sev-' + i.severity">{{ i.severity }}</span>
              <span style="font-size:13px;margin-left:8px">{{ i.description }}</span>
            </div>
          </div>
        </template>

        <!-- Deobfuscator Results -->
        <template v-else-if="toolId==='deobfus'">
          <div class="card">
            <div class="stats-grid">
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.results?.language }}</div><div class="stat-label">Language</div></div>
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.results?.layers }}</div><div class="stat-label">Layers</div></div>
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.iocs_found }}</div><div class="stat-label">IOCs Found</div></div>
            </div>
          </div>
          <div class="card">
            <div class="card-title" style="justify-content:space-between">
              Deobfuscated Code
              <button class="btn btn-secondary btn-sm" @click="copyText(result.results?.deobfuscated_code)">&#128203; Copy</button>
            </div>
            <pre class="result-block" style="max-height:400px;overflow-y:auto">{{ result.results?.deobfuscated_code }}</pre>
          </div>
          <div class="card" v-if="hasIocs(result.results?.iocs)">
            <div class="card-title">Extracted IOCs</div>
            <template v-for="(vals, type) in result.results.iocs" :key="type">
              <div v-if="vals && vals.length" style="margin-bottom:8px">
                <div class="text-muted" style="font-size:12px;margin-bottom:4px">{{ type }} ({{ vals.length }})</div>
                <div class="ioc-list"><span class="ioc-pill" v-for="v in vals" :key="v">{{ v }}</span></div>
              </div>
            </template>
          </div>
        </template>

        <!-- YARA Scanner Results -->
        <template v-else-if="toolId==='yara'">
          <div class="card">
            <div class="stats-grid">
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.rules_loaded }}</div><div class="stat-label">Rules Loaded</div></div>
              <div class="stat-card stat-card-sm" :class="result.statistics?.matches > 0 ? 'stat-malicious' : 'stat-clean'"><div class="stat-value">{{ result.statistics?.matches }}</div><div class="stat-label">Matches</div></div>
            </div>
          </div>
          <div class="card" v-if="result.results?.matches?.length">
            <div class="card-title">Matches</div>
            <div v-for="m in result.results.matches" :key="m.rule" style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
              <div style="display:flex;gap:8px;align-items:center">
                <strong>{{ m.rule }}</strong>
                <span :class="'sev-badge sev-' + m.severity">{{ m.severity }}</span>
              </div>
            </div>
          </div>
          <div class="card" v-else><p class="text-muted">No YARA matches found.</p></div>
        </template>

        <!-- Threat Feed Search Results -->
        <template v-else-if="toolId==='threatfeed'">
          <div class="card">
            <div class="card-title">{{ result.statistics?.total }} Results</div>
            <div class="table-wrap">
              <table><thead><tr><th>IOC</th><th>Type</th><th>Family</th><th>Confidence</th><th>Last Seen</th></tr></thead>
              <tbody>
                <tr v-for="r in result.results" :key="r.ioc">
                  <td class="text-mono" style="font-size:11px">{{ r.ioc }}</td>
                  <td>{{ r.type }}</td>
                  <td>{{ r.malware_family || '&#8212;' }}</td>
                  <td><div class="conf-bar"><div class="conf-fill" :style="{width: r.confidence + '%'}"></div></div> {{ r.confidence }}%</td>
                  <td class="text-muted" style="font-size:11px">{{ r.last_seen?.slice(0,10) }}</td>
                </tr>
                <tr v-if="!result.results?.length"><td colspan="5" class="text-muted">No results found.</td></tr>
              </tbody></table>
            </div>
          </div>
        </template>

        <!-- Threat Feed Update Results -->
        <template v-else-if="toolId==='feedupdate'">
          <div class="card">
            <div class="stats-grid">
              <div class="stat-card stat-card-sm stat-clean"><div class="stat-value">{{ result.statistics?.new_iocs }}</div><div class="stat-label">New IOCs</div></div>
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.duplicates_skipped }}</div><div class="stat-label">Duplicates</div></div>
              <div class="stat-card stat-card-sm"><div class="stat-value">{{ result.statistics?.update_time_seconds?.toFixed(1) }}s</div><div class="stat-label">Duration</div></div>
            </div>
          </div>
        </template>

        <!-- File Carver Results -->
        <template v-else-if="toolId==='carve'">
          <div class="card">
            <div class="card-title">{{ result.statistics?.files_carved }} Files Carved</div>
            <div class="table-wrap">
              <table><thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>SHA256</th></tr></thead>
              <tbody>
                <tr v-for="f in result.results?.files" :key="f.filename">
                  <td>{{ f.filename }}</td>
                  <td>{{ f.type }}</td>
                  <td>{{ formatSize(f.size) }}</td>
                  <td class="text-mono" style="font-size:10px">{{ f.hashes?.sha256?.slice(0,16) }}&#8230;</td>
                </tr>
                <tr v-if="!result.results?.files?.length"><td colspan="4" class="text-muted">No files carved.</td></tr>
              </tbody></table>
            </div>
          </div>
        </template>

        <!-- Generic fallback -->
        <template v-else>
          <div class="card">
            <div class="card-title">Results</div>
            <pre class="result-block">{{ resultFormatted }}</pre>
          </div>
        </template>

        <!-- Raw JSON toggle (available on all tool results) -->
        <div style="margin-top:8px;text-align:right">
          <button class="btn btn-secondary btn-sm" @click="showRaw=!showRaw">
            {{ showRaw ? 'Hide' : 'Show' }} Raw JSON
          </button>
        </div>
        <div v-if="showRaw" class="card">
          <div class="card-title" style="justify-content:space-between">
            Raw JSON
            <button class="btn btn-secondary btn-sm" @click="copyResult">&#128203; Copy</button>
          </div>
          <pre class="result-block">{{ resultFormatted }}</pre>
        </div>

      </template>
    </template>
  </div>`,
  setup() {
    const route = useRoute();
    const toolId = computed(() => route.params.id);
    const tool   = computed(() => ALL_TOOLS.find(t => t.id === toolId.value));

    // shared state
    const running = ref(false);
    const error   = ref("");
    const result  = ref(null);
    const resultFormatted = computed(() =>
      result.value ? JSON.stringify(result.value, null, 2) : ""
    );

    // result display state
    const showRaw = ref(false);
    const hashChartCanvas = ref(null);
    const pcapChartCanvas = ref(null);
    const iocChartCanvas  = ref(null);
    let   activeChart = null;

    watch(result, async (val) => {
      if (!val) return;
      showRaw.value = false;
      await nextTick();
      if (activeChart) { activeChart.destroy(); activeChart = null; }
      if (toolId.value === 'hash' && hashChartCanvas.value) {
        const v = val.statistics?.verdicts || {};
        activeChart = new Chart(hashChartCanvas.value, {
          type: 'doughnut',
          data: { labels: ['Clean','Suspicious','Malicious','Unknown'],
                  datasets: [{ data: [v.clean||0, v.suspicious||0, v.malicious||0, v.unknown||0],
                               backgroundColor: ['#3fb950','#e3b341','#f85149','#8b949e'], borderWidth: 0 }] },
          options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#c9d1d9' } } } }
        });
      }
      else if (toolId.value === 'pcap' && pcapChartCanvas.value) {
        const p = val.protocols || {};
        activeChart = new Chart(pcapChartCanvas.value, {
          type: 'doughnut',
          data: { labels: Object.keys(p), datasets: [{ data: Object.values(p), borderWidth: 0 }] },
          options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#c9d1d9' } } } }
        });
      }
      else if (toolId.value === 'ioc' && iocChartCanvas.value) {
        const r = val.results || {};
        const counts = { IPs: r.ips?.length||0, Domains: r.domains?.length||0, URLs: r.urls?.length||0,
                         Emails: r.emails?.length||0, Hashes: Object.values(r.hashes||{}).flat().length, CVEs: r.cves?.length||0 };
        const filtered = Object.fromEntries(Object.entries(counts).filter(([,v]) => v > 0));
        activeChart = new Chart(iocChartCanvas.value, {
          type: 'bar',
          data: { labels: Object.keys(filtered),
                  datasets: [{ data: Object.values(filtered), backgroundColor: '#58a6ff', borderRadius: 4 }] },
          options: { responsive: true, maintainAspectRatio: false,
                     plugins: { legend: { display: false } },
                     scales: { x: { ticks: { color: '#8b949e' } }, y: { ticks: { color: '#8b949e', stepSize: 1 } } } }
        });
      }
    });

    // per-tool state
    const iocText      = ref(""); const uploadedFile = ref(null); const fileName = ref("");
    const hashText     = ref("");
    const intelTarget  = ref("");
    const urlText      = ref("");
    const logFormat    = ref("auto");
    const yaraRules    = ref("");
    const certHost     = ref(""); const certPort = ref(443);
    const deobLang     = ref("auto"); const deobCode = ref("");
    const feedQuery    = ref("");

    function onFileChange(e, _type) {
      uploadedFile.value = e.target.files[0] || null;
      fileName.value = uploadedFile.value?.name || "";
    }

    async function runTool(path, bodyOrForm) {
      running.value = true; error.value = ""; result.value = null;
      try {
        const isForm = bodyOrForm instanceof FormData;
        const res = await apiFetch(path, {
          method: "POST",
          body: isForm ? bodyOrForm : JSON.stringify(bodyOrForm),
        });
        const data = await res.json();
        if (!res.ok) { error.value = data.error || "Request failed"; }
        else { result.value = data; }
      } catch (e) { error.value = "Network error: " + e.message; }
      running.value = false;
    }

    async function runIoc() {
      if (uploadedFile.value) {
        const fd = new FormData();
        fd.append("file", uploadedFile.value);
        await runTool("/api/ioc/extract", fd);
      } else {
        await runTool("/api/ioc/extract", { text: iocText.value });
      }
    }
    async function runHash() {
      const hashes = hashText.value.trim().split(/\s+/).filter(Boolean);
      await runTool("/api/hash/lookup", { hashes });
    }
    async function runIntel() {
      const targets = intelTarget.value.trim().split(/\n/).filter(Boolean);
      await runTool("/api/intel/analyze", { targets });
    }
    async function runUrl() {
      const urls = urlText.value.trim().split(/\n/).filter(Boolean);
      await runTool("/api/url/analyze", { urls });
    }
    async function runLog() {
      const fd = new FormData();
      fd.append("file", uploadedFile.value);
      fd.append("format", logFormat.value);
      await runTool("/api/log/analyze", fd);
    }
    async function runEml() {
      const fd = new FormData();
      fd.append("file", uploadedFile.value);
      await runTool("/api/eml/parse", fd);
    }
    async function runYara() {
      const fd = new FormData();
      fd.append("file", uploadedFile.value);
      if (yaraRules.value) fd.append("rules", new Blob([yaraRules.value], { type: "text/plain" }), "rules.yar");
      await runTool("/api/yara/scan", fd);
    }
    async function runCert()    { await runTool("/api/cert/analyze", { hostname: certHost.value, port: certPort.value }); }
    async function runDeobfus() { await runTool("/api/deobfuscate", { code: deobCode.value, language: deobLang.value }); }
    async function runPcap()    { const fd = new FormData(); fd.append("file", uploadedFile.value); await runTool("/api/pcap/analyze", fd); }
    async function runFeedSearch() { await runTool("/api/threatfeed/search", { query: feedQuery.value }); }
    async function runFeedUpdate() { await runTool("/api/threatfeed/update", {}); }
    async function runCarve()   { const fd = new FormData(); fd.append("file", uploadedFile.value); await runTool("/api/carve/extract", fd); }

    async function copyResult() {
      await navigator.clipboard.writeText(JSON.stringify(result.value, null, 2));
    }

    function riskColor(score) {
      if (score >= 70) return 'color:#f85149';
      if (score >= 40) return 'color:#e3b341';
      return 'color:#3fb950';
    }
    function triggeredChecks(r) {
      return Object.entries(r.heuristic_checks || {}).filter(([,v]) => v).map(([k]) => k.replace(/_/g,' '));
    }
    function authBadge(val) {
      if (!val) return 'pill';
      if (val.toLowerCase().includes('pass')) return 'pill pill-success';
      if (val.toLowerCase().includes('fail')) return 'pill pill-danger';
      return 'pill';
    }
    function formatSize(bytes) {
      if (!bytes) return '0 B';
      const units = ['B','KB','MB','GB'];
      let i = 0; let n = bytes;
      while (n >= 1024 && i < 3) { n /= 1024; i++; }
      return n.toFixed(1) + ' ' + units[i];
    }
    function formatDns(records) {
      if (!records) return '—';
      return Object.entries(records).map(([k,v]) => `${k}: ${Array.isArray(v) ? v.slice(0,2).join(', ') : v}`).join(' | ');
    }
    function hasIocs(iocs) {
      return iocs && Object.values(iocs).some(v => v?.length > 0);
    }
    const allHashes = computed(() => {
      const h = result.value?.results?.hashes || {};
      return [
        ...(h.md5 || []).map(v => ({value: v, type: 'MD5'})),
        ...(h.sha1 || []).map(v => ({value: v, type: 'SHA1'})),
        ...(h.sha256 || []).map(v => ({value: v, type: 'SHA256'})),
      ];
    });

    return {
      toolId, tool, running, error, result, resultFormatted,
      iocText, uploadedFile, fileName, hashText, intelTarget, urlText,
      logFormat, yaraRules, certHost, certPort, deobLang, deobCode, feedQuery,
      onFileChange, runIoc, runHash, runIntel, runUrl, runLog, runEml,
      runYara, runCert, runDeobfus, runPcap, runFeedSearch, runFeedUpdate, runCarve,
      copyResult,
      showRaw, hashChartCanvas, pcapChartCanvas, iocChartCanvas,
      riskColor, triggeredChecks, authBadge, formatSize, formatDns, hasIocs, copyText, allHashes,
    };
  },
};

// ── Profile ───────────────────────────────────────────────────────────────────
const ProfileView = {
  template: `
  <div>
    <div class="page-title">👤 My Profile</div>
    <div class="card">
      <div class="card-title">Account Details</div>
      <table>
        <tr><td class="text-muted" style="width:160px">Username</td><td>{{ user.username }}</td></tr>
        <tr><td class="text-muted">Email</td><td>{{ user.email }}</td></tr>
        <tr><td class="text-muted">Role</td><td><span :class="'pill pill-' + rolePill">{{ user.role }}</span></td></tr>
        <tr><td class="text-muted">MFA</td><td><span :class="user.mfa_enabled ? 'pill pill-success' : 'pill'">{{ user.mfa_enabled ? 'Enabled' : 'Disabled' }}</span></td></tr>
        <tr><td class="text-muted">Created</td><td class="text-mono">{{ user.created_at }}</td></tr>
        <tr><td class="text-muted">Last Login</td><td class="text-mono">{{ user.last_login || 'N/A' }}</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title" style="justify-content:space-between">
        Two-Factor Authentication
        <span :class="user.mfa_enabled ? 'pill pill-success' : 'pill'">{{ user.mfa_enabled ? 'Enabled' : 'Disabled' }}</span>
      </div>
      <div v-if="mfaMsg" :class="'alert alert-' + mfaMsgType">{{ mfaMsg }}</div>

      <!-- Setup flow (MFA not enabled) -->
      <template v-if="!user.mfa_enabled">
        <button v-if="!mfaSetupData" class="btn btn-secondary" :disabled="mfaLoading" @click="startMfaSetup">
          <span v-if="mfaLoading" class="spinner"></span> Enable MFA
        </button>
        <template v-if="mfaSetupData">
          <p style="font-size:13px;color:var(--text-muted);margin:12px 0">Scan the URI or enter the secret manually in your authenticator app (Google Authenticator, Authy, etc.).</p>
          <div class="form-group">
            <label class="form-label">TOTP Secret</label>
            <div style="display:flex;gap:8px;align-items:center">
              <code class="mfa-secret">{{ mfaSetupData.secret }}</code>
              <button class="btn btn-secondary btn-sm" @click="copyText(mfaSetupData.secret)">&#128203;</button>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Provisioning URI</label>
            <a :href="mfaSetupData.provisioning_uri" class="text-mono" style="font-size:11px;word-break:break-all">{{ mfaSetupData.provisioning_uri }}</a>
          </div>
          <div class="form-group">
            <label class="form-label">Enter 6-digit code to verify</label>
            <input v-model="mfaCode" class="form-control" placeholder="000000" maxlength="6" style="width:140px" />
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary" :disabled="mfaLoading || mfaCode.length!==6" @click="verifyMfa">
              <span v-if="mfaLoading" class="spinner"></span> Activate MFA
            </button>
            <button class="btn btn-secondary" @click="mfaSetupData=null;mfaCode=''">Cancel</button>
          </div>
        </template>
      </template>

      <!-- Disable flow (MFA enabled) -->
      <template v-else>
        <button v-if="!showDisableMfa" class="btn btn-danger" @click="showDisableMfa=true">Disable MFA</button>
        <template v-if="showDisableMfa">
          <div class="form-group" style="margin-top:12px">
            <label class="form-label">Confirm your password</label>
            <input v-model="mfaDisablePw" type="password" class="form-control" style="width:240px" />
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-danger" :disabled="mfaLoading || !mfaDisablePw" @click="disableMfa">
              <span v-if="mfaLoading" class="spinner"></span> Confirm Disable
            </button>
            <button class="btn btn-secondary" @click="showDisableMfa=false;mfaDisablePw=''">Cancel</button>
          </div>
        </template>
      </template>
    </div>

    <div class="card">
      <div class="card-title">Change Password</div>
      <div v-if="pwMsg" :class="'alert alert-' + pwMsgType">{{ pwMsg }}</div>
      <div class="form-group">
        <label class="form-label">Current Password</label>
        <input v-model="currentPw" type="password" class="form-control" />
      </div>
      <div class="form-group">
        <label class="form-label">New Password</label>
        <input v-model="newPw" type="password" class="form-control" />
      </div>
      <button class="btn btn-primary" :disabled="pwLoading" @click="changePw">
        <span v-if="pwLoading" class="spinner"></span> Update Password
      </button>
    </div>

    <div class="card">
      <div class="card-title" style="justify-content:space-between">
        API Keys
        <button class="btn btn-secondary btn-sm" @click="showCreateKey=true">+ New Key</button>
      </div>
      <div v-if="showCreateKey" style="margin-bottom:14px">
        <div class="form-group">
          <label class="form-label">Key Name</label>
          <input v-model="newKeyName" class="form-control" placeholder="my-script-key" />
        </div>
        <button class="btn btn-primary btn-sm" :disabled="keyLoading" @click="createKey">
          <span v-if="keyLoading" class="spinner"></span> Create
        </button>
        <button class="btn btn-secondary btn-sm" @click="showCreateKey=false;newKeyName=''">Cancel</button>
      </div>
      <div v-if="newKeyValue" class="alert alert-success">
        New key (save now — shown once):
        <br/><code style="font-family:monospace;word-break:break-all">{{ newKeyValue }}</code>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Prefix</th><th>Created</th><th>Last Used</th><th></th></tr></thead>
          <tbody>
            <tr v-for="k in apiKeys" :key="k.id">
              <td>{{ k.name }}</td>
              <td class="text-mono">{{ k.key_prefix }}…</td>
              <td class="text-mono">{{ k.created_at?.slice(0,10) }}</td>
              <td class="text-mono">{{ k.last_used?.slice(0,10) || 'Never' }}</td>
              <td><button class="btn btn-danger btn-sm" @click="revokeKey(k.id)">Revoke</button></td>
            </tr>
            <tr v-if="!apiKeys.length"><td colspan="5" class="text-muted">No API keys</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>`,
  setup() {
    const user = computed(() => auth.user || {});
    const rolePill = computed(() => ({ admin: "admin", senior_analyst: "senior", analyst: "analyst" }[user.value.role] || "viewer");
    const currentPw = ref(""); const newPw = ref("");
    const pwMsg = ref(""); const pwMsgType = ref(""); const pwLoading = ref(false);
    const apiKeys = ref([]); const showCreateKey = ref(false); const newKeyName = ref("");
    const newKeyValue = ref(""); const keyLoading = ref(false);

    // MFA state
    const mfaLoading = ref(false); const mfaMsg = ref(""); const mfaMsgType = ref("");
    const mfaSetupData = ref(null); const mfaCode = ref("");
    const showDisableMfa = ref(false); const mfaDisablePw = ref("");

    onMounted(async () => {
      const r = await apiFetch("/api/auth/keys");
      if (r.ok) { const d = await r.json(); apiKeys.value = d.keys || []; }
    });

    async function changePw() {
      pwLoading.value = true; pwMsg.value = "";
      const res = await apiFetch("/api/auth/me/password", {
        method: "PUT", body: JSON.stringify({ current_password: currentPw.value, new_password: newPw.value }),
      });
      const d = await res.json();
      pwMsg.value = res.ok ? d.message : d.error;
      pwMsgType.value = res.ok ? "success" : "error";
      if (res.ok) { currentPw.value = ""; newPw.value = ""; }
      pwLoading.value = false;
    }

    async function createKey() {
      keyLoading.value = true; newKeyValue.value = "";
      const res = await apiFetch("/api/auth/keys", {
        method: "POST", body: JSON.stringify({ name: newKeyName.value }),
      });
      const d = await res.json();
      if (res.ok) {
        newKeyValue.value = d.api_key;
        showCreateKey.value = false; newKeyName.value = "";
        const r2 = await apiFetch("/api/auth/keys");
        if (r2.ok) { const d2 = await r2.json(); apiKeys.value = d2.keys || []; }
      }
      keyLoading.value = false;
    }

    async function revokeKey(id) {
      await apiFetch(`/api/auth/keys/${id}`, { method: "DELETE" });
      apiKeys.value = apiKeys.value.filter(k => k.id !== id);
    }

    async function startMfaSetup() {
      mfaLoading.value = true; mfaMsg.value = "";
      const res = await apiFetch("/api/auth/mfa/setup", { method: "POST" });
      const d = await res.json();
      if (res.ok) { mfaSetupData.value = d; }
      else { mfaMsg.value = d.error || "MFA setup failed"; mfaMsgType.value = "error"; }
      mfaLoading.value = false;
    }

    async function verifyMfa() {
      mfaLoading.value = true; mfaMsg.value = "";
      const res = await apiFetch("/api/auth/mfa/verify", {
        method: "POST", body: JSON.stringify({ totp_code: mfaCode.value }),
      });
      const d = await res.json();
      if (res.ok) {
        mfaMsg.value = "MFA enabled!"; mfaMsgType.value = "success";
        mfaSetupData.value = null; mfaCode.value = "";
        await fetchMe();
      } else { mfaMsg.value = d.error || "Invalid code"; mfaMsgType.value = "error"; }
      mfaLoading.value = false;
    }

    async function disableMfa() {
      mfaLoading.value = true; mfaMsg.value = "";
      const res = await apiFetch("/api/auth/mfa", {
        method: "DELETE", body: JSON.stringify({ password: mfaDisablePw.value }),
      });
      const d = await res.json();
      if (res.ok) {
        mfaMsg.value = "MFA disabled."; mfaMsgType.value = "success";
        showDisableMfa.value = false; mfaDisablePw.value = "";
        await fetchMe();
      } else { mfaMsg.value = d.error || "Incorrect password"; mfaMsgType.value = "error"; }
      mfaLoading.value = false;
    }

    return { user, rolePill, currentPw, newPw, pwMsg, pwMsgType, pwLoading, changePw,
             apiKeys, showCreateKey, newKeyName, newKeyValue, keyLoading, createKey, revokeKey,
             mfaLoading, mfaMsg, mfaMsgType, mfaSetupData, mfaCode,
             showDisableMfa, mfaDisablePw, startMfaSetup, verifyMfa, disableMfa, copyText };
  },
};

// ── Admin ─────────────────────────────────────────────────────────────────────
const AdminView = {
  template: `
  <div>
    <div class="page-title">⚙️ Administration</div>

    <div class="card">
      <div class="card-title" style="justify-content:space-between">
        Users
        <button class="btn btn-secondary btn-sm" @click="loadUsers">↻ Refresh</button>
      </div>
      <div v-if="usersError" class="alert alert-error">{{ usersError }}</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody>
            <tr v-for="u in users" :key="u.id">
              <td>{{ u.username }}</td>
              <td class="text-muted">{{ u.email }}</td>
              <td>
                <select :value="u.role" @change="changeRole(u.id, $event.target.value)" class="form-control" style="padding:3px 6px;width:auto">
                  <option>viewer</option><option>analyst</option><option>senior_analyst</option><option>admin</option>
                </select>
              </td>
              <td><span :class="u.is_active ? 'pill pill-success' : 'pill pill-danger'">{{ u.is_active ? 'Active' : 'Inactive' }}</span></td>
              <td class="text-mono">{{ u.created_at?.slice(0,10) }}</td>
              <td>
                <button v-if="u.is_active" class="btn btn-danger btn-sm" @click="toggleUser(u.id,'deactivate')">Deactivate</button>
                <button v-else class="btn btn-secondary btn-sm" @click="toggleUser(u.id,'activate')">Activate</button>
              </td>
            </tr>
            <tr v-if="!users.length"><td colspan="6" class="text-muted">No users found</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-title" style="justify-content:space-between">
        Audit Log
        <button class="btn btn-secondary btn-sm" @click="loadAudit">↻ Refresh</button>
      </div>
      <div v-if="auditError" class="alert alert-error">{{ auditError }}</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>IP</th><th>Status</th></tr></thead>
          <tbody>
            <tr v-for="e in auditLog" :key="e.id">
              <td class="text-mono" style="white-space:nowrap">{{ e.timestamp?.slice(0,19).replace('T',' ') }}</td>
              <td>{{ e.username || '—' }}</td>
              <td class="text-mono" style="font-size:11px">{{ e.action }}</td>
              <td class="text-mono">{{ e.ip_address || '—' }}</td>
              <td><span :class="statusPill(e.status_code)">{{ e.status_code || '—' }}</span></td>
            </tr>
            <tr v-if="!auditLog.length"><td colspan="5" class="text-muted">No audit entries</td></tr>
          </tbody>
        </table>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;align-items:center">
        <button class="btn btn-secondary btn-sm" :disabled="auditOffset===0" @click="auditOffset=Math.max(0,auditOffset-auditLimit);loadAudit()">← Prev</button>
        <span class="text-muted" style="font-size:12px">Offset {{ auditOffset }}</span>
        <button class="btn btn-secondary btn-sm" :disabled="auditLog.length < auditLimit" @click="auditOffset+=auditLimit;loadAudit()">Next →</button>
      </div>
    </div>
  </div>`,
  setup() {
    const users = ref([]); const usersError = ref("");
    const auditLog = ref([]); const auditError = ref("");
    const auditOffset = ref(0); const auditLimit = 50;

    async function loadUsers() {
      usersError.value = "";
      const res = await apiFetch("/api/admin/users");
      if (res.ok) { const d = await res.json(); users.value = d.users || []; }
      else { const d = await res.json(); usersError.value = d.error || "Failed to load users"; }
    }

    async function loadAudit() {
      auditError.value = "";
      const res = await apiFetch(`/api/admin/audit?limit=${auditLimit}&offset=${auditOffset.value}`);
      if (res.ok) { const d = await res.json(); auditLog.value = d.audit_log || []; }
      else { const d = await res.json(); auditError.value = d.error || "Failed to load audit log"; }
    }

    async function changeRole(userId, role) {
      await apiFetch(`/api/admin/users/${userId}/role`, {
        method: "PUT", body: JSON.stringify({ role }),
      });
      await loadUsers();
    }

    async function toggleUser(userId, action) {
      await apiFetch(`/api/admin/users/${userId}/${action}`, { method: "PUT" });
      await loadUsers();
    }

    function statusPill(code) {
      if (!code) return "pill";
      if (code < 300) return "pill pill-success";
      if (code < 400) return "pill";
      if (code < 500) return "pill pill-danger";
      return "pill pill-danger";
    }

    onMounted(() => { loadUsers(); loadAudit(); });
    return { users, usersError, auditLog, auditError, auditOffset, auditLimit,
             loadUsers, loadAudit, changeRole, toggleUser, statusPill };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────────────────
const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/",           redirect: "/dashboard" },
    { path: "/login",      component: LoginView },
    { path: "/dashboard",  component: DashboardView, meta: { auth: true } },
    { path: "/tools",      component: ToolsListView, meta: { auth: true } },
    { path: "/tools/:id",  component: ToolView,      meta: { auth: true } },
    { path: "/profile",    component: ProfileView,    meta: { auth: true } },
    { path: "/admin",      component: AdminView,      meta: { auth: true, role: "admin" } },
    { path: "/:pathMatch(.*)*", redirect: "/dashboard" },
  ],
});

// Auth guard
router.beforeEach(async (to) => {
  if (!to.meta.auth) return true;
  if (!auth.accessToken) return "/login";
  if (!auth.user) await fetchMe();
  if (!auth.user) return "/login";
  if (to.meta.role) {
    const roleLevel = { viewer: 0, analyst: 1, senior_analyst: 2, admin: 3 };
    if ((roleLevel[auth.role] || 0) < (roleLevel[to.meta.role] || 0)) return "/dashboard";
  }
  return true;
});

// Import useRoute here after router is created
function useRoute() { return router.currentRoute.value; }

// ─────────────────────────────────────────────────────────────────────────────
// Root App component
// ─────────────────────────────────────────────────────────────────────────────
const App = {
  template: `
  <template v-if="!isLoggedIn">
    <router-view />
  </template>
  <template v-else>
    <nav class="navbar">
      <span class="navbar-brand">vlair <span>SecOps</span></span>
      <div class="navbar-spacer"></div>
      <div class="navbar-user">
        <span>{{ auth.user?.username }}</span>
        <span class="badge">{{ auth.user?.role }}</span>
        <button class="btn-link" @click="logout">Sign out</button>
      </div>
    </nav>
    <div class="layout">
      <aside class="sidebar">
        <div class="sidebar-section">Navigation</div>
        <router-link to="/dashboard" class="sidebar-link" active-class="active">
          <span class="icon">📊</span> Dashboard
        </router-link>
        <router-link to="/tools" class="sidebar-link" active-class="active">
          <span class="icon">🛠️</span> Tools
        </router-link>
        <div class="sidebar-section" style="margin-top:8px">Account</div>
        <router-link to="/profile" class="sidebar-link" active-class="active">
          <span class="icon">👤</span> Profile
        </router-link>
        <router-link v-if="isAdmin" to="/admin" class="sidebar-link" active-class="active">
          <span class="icon">⚙️</span> Admin
        </router-link>
      </aside>
      <main class="main-content">
        <router-view />
      </main>
    </div>
  </template>`,
  setup() {
    const isLoggedIn = computed(() => auth.isLoggedIn);
    const isAdmin    = computed(() => ["admin"].includes(auth.role));

    async function logout() {
      await apiFetch("/api/auth/logout", { method: "POST" }).catch(() => {});
      clearAuth();
      router.push("/login");
    }

    onMounted(async () => {
      if (auth.accessToken && !auth.user) await fetchMe();
    });

    return { auth, isLoggedIn, isAdmin, logout };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Mount
// ─────────────────────────────────────────────────────────────────────────────
const app = createApp(App);
app.use(router);
app.mount("#app");
