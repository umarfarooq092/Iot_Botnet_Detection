import { FormEvent, ReactNode, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import GlitchText from "./components/GlitchText";

type AuthResponse = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
};

type LoginApiResponse = {
  access_token?: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  mfa_pending?: string;
};

type HealthResponse = {
  status: string;
  service: string;
  environment: string;
  version: string;
};

type SummaryResponse = {
  devices_total: number;
  devices_active: number;
  devices_isolated: number;
  traffic_logs_total: number;
  alerts_total: number;
  alerts_open: number;
  alerts_high_severity: number;
  audit_entries_total: number;
};

type UserSummaryResponse = {
  devices_owned_total: number;
  devices_owned_active: number;
  devices_owned_isolated: number;
};

type AlertItem = {
  alert_id: string;
  device_id: string;
  rule_name: string;
  severity: string;
  message: string;
  status: string;
  created_at: string;
};

type DeviceItem = {
  device_id: string;
  name: string;
  status: string;
};

type UserItem = {
  username: string;
  role: string;
  failed_attempts: number;
  is_locked: boolean;
};

type RuleItem = {
  rule_id: string;
  rule_name: string;
  description: string;
  severity: string;
  enabled: boolean;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

type IngestResponse = {
  accepted: boolean;
  device_id: string;
  traffic_log_id: string;
  alerts_created: number;
};

type BackupSnapshot = {
  exported_at: string;
  users: Array<Record<string, unknown>>;
  devices: Array<Record<string, unknown>>;
  traffic_logs: Array<Record<string, unknown>>;
  alerts: Array<Record<string, unknown>>;
  audit_logs: Array<Record<string, unknown>>;
  rules: Array<Record<string, unknown>>;
};

// Helper functions for backup formatting
function convertToCsv(data: Array<Record<string, unknown>>): string {
  if (data.length === 0) return "";
  
  const headers = Object.keys(data[0]);
  const headerRow = headers.map(h => `"${h}"`).join(",");
  
  const rows = data.map(row => 
    headers.map(header => {
      const value = row[header];
      if (value === null || value === undefined) return "";
      const str = String(value);
      return `"${str.replace(/"/g, '""')}"`;
    }).join(",")
  );
  
  return [headerRow, ...rows].join("\n");
}

function downloadFile(content: string, filename: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function renderDataTable(title: string, data: Array<Record<string, unknown>>): JSX.Element {
  if (data.length === 0) {
    return <p style={{ color: "#999" }}>No {title} data</p>;
  }

  const headers = Object.keys(data[0]);
  
  return (
    <div style={{ marginBottom: "30px" }}>
      <h3 style={{ color: "#fff", marginBottom: "10px", backgroundColor: "#1a1a2e", padding: "10px", borderRadius: "4px" }}>
        {title} ({data.length} records)
      </h3>
      <div style={{ 
        overflowX: "auto", 
        marginBottom: "15px",
        backgroundColor: "#16213e",
        padding: "15px",
        borderRadius: "6px",
        border: "1px solid #0f3460"
      }}>
        <table style={{
          borderCollapse: "collapse",
          width: "100%",
          fontSize: "13px",
          minWidth: "100%"
        }}>
          <thead>
            <tr style={{ backgroundColor: "#0f3460" }}>
              {headers.map((h, i) => (
                <th key={i} style={{
                  padding: "12px",
                  textAlign: "left",
                  fontWeight: "bold",
                  color: "#e94560",
                  borderRight: i < headers.length - 1 ? "1px solid #1a3a52" : "none",
                  whiteSpace: "nowrap"
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, rowIdx) => (
              <tr key={rowIdx} style={{
                backgroundColor: rowIdx % 2 === 0 ? "#0f3460" : "#1a4d6d",
                borderBottom: "1px solid #1a3a52",
                transition: "background-color 0.2s"
              }} 
              onMouseEnter={(e) => {
                const row = e.currentTarget;
                row.style.backgroundColor = "#16596d";
              }}
              onMouseLeave={(e) => {
                const row = e.currentTarget;
                row.style.backgroundColor = rowIdx % 2 === 0 ? "#0f3460" : "#1a4d6d";
              }}>
                {headers.map((h, colIdx) => (
                  <td key={colIdx} style={{
                    padding: "10px 12px",
                    borderRight: colIdx < headers.length - 1 ? "1px solid #1a3a52" : "none",
                    color: "#e0e0e0",
                    wordWrap: "break-word",
                    maxWidth: "200px"
                  }}>
                    {row[h] === null ? <span style={{ color: "#888", fontStyle: "italic" }}>null</span> : 
                     row[h] === true ? <span style={{ color: "#4ade80", fontWeight: "bold" }}>✓ true</span> :
                     row[h] === false ? <span style={{ color: "#ef4444", fontWeight: "bold" }}>✗ false</span> :
                     String(row[h]).length > 100 ? String(row[h]).substring(0, 100) + "..." : String(row[h])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";

function readRoleFromToken(token: string): string {
  try {
    const payload = token.split(".")[1];
    if (!payload) {
      return "";
    }
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = JSON.parse(atob(normalized)) as { role?: string };
    return decoded.role || "";
  } catch {
    return "";
  }
}

function isStrongPassword(password: string): boolean {
  if (password.length < 12) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^\w\s]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSpecial;
}

function useApiClient() {
  const navigate = useNavigate();
  const [token, setToken] = useState(sessionStorage.getItem("access_token") || "");
  const [refreshToken, setRefreshToken] = useState(sessionStorage.getItem("refresh_token") || "");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [mfaPending, setMfaPending] = useState("");

  useEffect(() => {
    if (token) {
      sessionStorage.setItem("access_token", token);
    } else {
      sessionStorage.removeItem("access_token");
    }
  }, [token]);

  useEffect(() => {
    if (refreshToken) {
      sessionStorage.setItem("refresh_token", refreshToken);
    } else {
      sessionStorage.removeItem("refresh_token");
    }
  }, [refreshToken]);

  async function readJson(response: Response): Promise<Record<string, unknown>> {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return response.json().catch(() => ({}));
    }

    const rawText = await response.text().catch(() => "");
    if (rawText.trim().toLowerCase().startsWith("<!doctype")) {
      return {
        detail: "Received HTML instead of API JSON. Confirm backend is running at http://127.0.0.1:8000 and VITE_API_BASE_URL points to /api/v1.",
      };
    }

    return {};
  }

  async function apiGet<T>(path: string, authToken?: string): Promise<T> {
    const headers: Record<string, string> = {};
    if (authToken) {
      headers.Authorization = `Bearer ${authToken}`;
    }
    const response = await fetch(`${API_BASE}${path}`, { headers });
    const body = await readJson(response);
    if (!response.ok) {
      throw new Error((body.detail as string) || (body.message as string) || "Request failed");
    }
    return body as T;
  }

  async function apiPost<T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json", ...(extraHeaders || {}) };
    if (authToken) {
      headers.Authorization = `Bearer ${authToken}`;
    }
    console.log(`📤 POST ${API_BASE}${path}`, body);
    const response = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    console.log(`📥 Response Status: ${response.status}`, response.headers);
    const data = await readJson(response);
    console.log(`📄 Response Data:`, data);
    if (!response.ok) {
      throw new Error((data.detail as string) || (data.message as string) || "Request failed");
    }
    return data as T;
  }

  async function apiPatch<T>(path: string, body: unknown, authToken?: string): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (authToken) {
      headers.Authorization = `Bearer ${authToken}`;
    }
    const response = await fetch(`${API_BASE}${path}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });
    const data = await readJson(response);
    if (!response.ok) {
      throw new Error((data.detail as string) || (data.message as string) || "Request failed");
    }
    return data as T;
  }

  async function login(username: string, password: string) {
    console.log("🔐 Login attempt:", username);
    const auth = await apiPost<LoginApiResponse>("/auth/login", { username, password });
    if (auth.token_type === "mfa_pending" && auth.mfa_pending) {
      setMfaPending(auth.mfa_pending);
      setStatus("MFA code required. Enter your 6-digit authenticator code.");
      setError("");
      return;
    }

    if (!auth.access_token || !auth.refresh_token) {
      throw new Error("Login response missing tokens");
    }

    console.log("✅ Login response received:", { access_token: auth.access_token?.substring(0, 20) + "...", refresh_token: auth.refresh_token?.substring(0, 20) + "..." });
    setToken(auth.access_token);
    setRefreshToken(auth.refresh_token);
    setMfaPending("");
    setStatus("Signed in successfully.");
    setError("");
    console.log("🚀 Navigating to dashboard");
    navigate("/dashboard");
  }

  async function validateMfa(code: string) {
    if (!mfaPending) {
      throw new Error("No MFA challenge is active");
    }

    const auth = await apiPost<AuthResponse>("/auth/mfa/validate", { mfa_pending: mfaPending, code });
    setToken(auth.access_token);
    setRefreshToken(auth.refresh_token);
    setMfaPending("");
    setStatus("MFA verified. Signed in successfully.");
    setError("");
    navigate("/dashboard");
  }

  async function register(username: string, password: string) {
    if (!isStrongPassword(password)) {
      throw new Error("Password must be 12+ chars and include uppercase, lowercase, number, and special character.");
    }
    const auth = await apiPost<AuthResponse>("/auth/register", { username, password, role: "admin" });
    setToken(auth.access_token);
    setRefreshToken(auth.refresh_token);
    setStatus("Account created and signed in.");
    setError("");
    navigate("/dashboard");
  }

  function logout() {
    setToken("");
    setRefreshToken("");
    setMfaPending("");
    setStatus("Logged out.");
    setError("");
    navigate("/");
  }

  const role = token ? readRoleFromToken(token) : "";

  return { token, refreshToken, role, status, error, mfaPending, apiGet, apiPost, apiPatch, login, validateMfa, register, logout };
}

function AppShell({ children, token, role, logout }: { children: ReactNode; token: string; role: string; logout: () => void }) {
  return (
    <div className="site-shell">
      <header className="topbar">
        <div>
          <p className="kicker">Live threat operations</p>
          <h1>IoT Defense Command</h1>
        </div>
        <div className="topbar-actions">
          {!token ? <Link className="header-button" to="/login">Login</Link> : null}
          {!token ? <Link className="header-button secondary" to="/register">Register</Link> : null}
          {token ? <button className="header-button secondary" onClick={logout} type="button">Logout</button> : null}
        </div>
      </header>

      {token && role === "admin" ? (
        <nav className="admin-nav" aria-label="Admin portal navigation">
          <Link className="admin-nav-link" to="/dashboard">Dashboard</Link>
          <Link className="admin-nav-link" to="/devices">Devices</Link>
          <Link className="admin-nav-link" to="/alerts">Alerts</Link>
          <Link className="admin-nav-link" to="/rules">Rules</Link>
          <Link className="admin-nav-link" to="/response">Response</Link>
          <Link className="admin-nav-link" to="/backup">Backup</Link>
          <Link className="admin-nav-link" to="/session">Session</Link>
        </nav>
      ) : null}

      <main className="content-area content-area-full">{children}</main>
    </div>
  );
}

function LandingPage() {
  return (
    <section className="hero-card">
      <div className="hero-main hero-main-centered">
        <p className="hero-tag">Threat visibility. Fast response.</p>
        <GlitchText speed={0.9} enableShadows={true} enableOnHover={false} className="hero-glitch-title">
          See hostile IoT traffic, isolate compromised devices, and keep the network moving.
        </GlitchText>
        <p className="hero-copy">A live security console for monitoring devices, triaging alerts, triggering containment, and reviewing audit-ready snapshots in one place.</p>
        <div className="feature-grid">
          <article className="feature-card">
            <strong>Live telemetry</strong>
            <span>Track devices and traffic in real time.</span>
          </article>
          <article className="feature-card">
            <strong>Alert triage</strong>
            <span>Inspect suspicious patterns and rule hits.</span>
          </article>
          <article className="feature-card">
            <strong>Containment</strong>
            <span>Isolate a device with one admin action.</span>
          </article>
        </div>
        <div className="button-row hero-actions hero-actions-center">
          <Link className="cta-button" to="/login">Get Started</Link>
        </div>
      </div>
    </section>
  );
}

function AuthPage({
  mode,
  onSubmit,
  mfaPending,
  onValidateMfa,
}: {
  mode: "login" | "register";
  onSubmit: (username: string, password: string) => Promise<void>;
  mfaPending?: string;
  onValidateMfa?: (code: string) => Promise<void>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setLocalError("");
    try {
      await onSubmit(username, password);
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Request failed";
      setLocalError(message);
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa(event: FormEvent) {
    event.preventDefault();
    if (!onValidateMfa) {
      return;
    }
    setBusy(true);
    setLocalError("");
    try {
      await onValidateMfa(mfaCode);
      setMfaCode("");
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Request failed";
      setLocalError(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="auth-stage">
      <section className="panel auth-panel">
        <h2>{mode === "login" ? "Login" : "Register"}</h2>
        <form className="grid-form" autoComplete="off" onSubmit={submit}>
          <label>
            Username
            <input autoComplete="off" name="admin-username" onChange={(event) => setUsername(event.target.value)} placeholder="Enter username" value={username} />
          </label>
          <label>
            Password
            <input autoComplete="new-password" name="admin-password" onChange={(event) => setPassword(event.target.value)} placeholder="Enter password" type="password" value={password} />
          </label>
          {mode === "register" ? (
            <p style={{ marginTop: "4px", fontSize: "13px", opacity: 0.85 }}>
              Password rules: minimum 12 characters with uppercase, lowercase, number, and special character.
            </p>
          ) : null}
          <button disabled={busy} type="submit">
            {mode === "login" ? "Sign In" : "Create Account"}
          </button>
        </form>
        {mode === "login" && mfaPending ? (
          <form className="grid-form" onSubmit={submitMfa} style={{ marginTop: "14px" }}>
            <h3 style={{ marginBottom: "8px" }}>MFA Verification</h3>
            <label>
              6-digit code
              <input
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={6}
                name="mfa-code"
                onChange={(event) => setMfaCode(event.target.value)}
                placeholder="123456"
                value={mfaCode}
              />
            </label>
            <button disabled={busy || mfaCode.length !== 6} type="submit">Verify MFA</button>
          </form>
        ) : null}
        {localError ? <p className="error">{localError}</p> : null}
      </section>

      <aside className="auth-side-copy">
        <p className="hero-tag">Secure access gateway</p>
        <h3>{mode === "login" ? "Command your defense stack" : "Create your operator profile"}</h3>
        <p>
          {mode === "login"
            ? "Enter your credentials to monitor threats, inspect alerts, and isolate compromised IoT devices from one control surface."
            : "Register to access live telemetry, response actions, and audit-ready workflows built for secure IoT operations."}
        </p>
      </aside>
    </section>
  );
}

function RequireAuth({ token, children }: { token: string; children: ReactNode }) {
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function RequireAdmin({ token, role, children }: { token: string; role: string; children: ReactNode }) {
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (role !== "admin") {
    return (
      <section className="panel">
        <h2>Admin access required</h2>
        <p>This workspace is configured for admin-only operations.</p>
      </section>
    );
  }
  return <>{children}</>;
}

function HealthPage({ apiGet }: { apiGet: <T>(path: string, authToken?: string) => Promise<T> }) {
  const [data, setData] = useState<HealthResponse | null>(null);

  async function load() {
    setData(await apiGet<HealthResponse>("/health"));
  }

  return (
    <section className="panel">
      <h2>Health</h2>
      <p>Public backend status check.</p>
      <button onClick={() => void load()} type="button">Check service</button>
      {data ? <pre>{JSON.stringify(data, null, 2)}</pre> : null}
    </section>
  );
}

function UserDashboardPage({ apiGet, apiPost, token }: { apiGet: <T>(path: string, authToken?: string) => Promise<T>; apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string }) {
  const [summary, setSummary] = useState<UserSummaryResponse | null>(null);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selected, setSelected] = useState("");
  const [reason, setReason] = useState("Owner action from user dashboard");
  const [deviceId, setDeviceId] = useState("user-device-001");
  const [name, setName] = useState("My Device");
  const [apiKey, setApiKey] = useState("my-device-key-001");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  async function refreshData() {
    const [summaryData, deviceData, alertData] = await Promise.all([
      apiGet<UserSummaryResponse>("/dashboard/summary", token),
      apiGet<DeviceItem[]>("/devices", token),
      apiGet<AlertItem[]>("/alerts", token),
    ]);
    setSummary(summaryData);
    setDevices(deviceData);
    setAlerts(alertData);
    if (!selected && deviceData.length > 0) {
      setSelected(deviceData[0].device_id);
    }
  }

  async function registerDevice(event: FormEvent) {
    event.preventDefault();
    setResult(await apiPost("/devices/register", { device_id: deviceId, name, api_key: apiKey }, token));
    await refreshData();
  }

  async function isolateSelected() {
    if (!selected) return;
    setResult(await apiPost("/response/isolate-device", { device_id: selected, reason }, token));
    await refreshData();
  }

  async function deisolateSelected() {
    if (!selected) return;
    setResult(await apiPost("/response/deisolate-device", { device_id: selected, reason }, token));
    await refreshData();
  }

  useEffect(() => {
    void refreshData().catch(() => {
      setSummary(null);
      setDevices([]);
      setAlerts([]);
    });
    const timer = window.setInterval(() => {
      void refreshData().catch(() => {
        setAlerts([]);
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [apiGet, token]);

  return (
    <section className="stacked">
      <section className="hero-card">
        <p className="hero-tag">User Dashboard</p>
        <h2>Welcome operator</h2>
        <p>Manage your own devices here. Admin-level controls over all users/devices remain restricted.</p>
      </section>
      <section className="summary-grid">
        <Stat label="My Devices" value={summary?.devices_owned_total ?? 0} />
        <Stat label="My Active" value={summary?.devices_owned_active ?? 0} />
        <Stat label="My Isolated" value={summary?.devices_owned_isolated ?? 0} />
        <Stat label="Role" value={0} />
      </section>
      <section className="panel">
        <h3>My devices</h3>
        <label>
          Selected device
          <select onChange={(event) => setSelected(event.target.value)} value={selected}>
            <option value="">Select your device</option>
            {devices.map((device) => (
              <option key={device.device_id} value={device.device_id}>
                {device.name} ({device.device_id}) - {device.status}
              </option>
            ))}
          </select>
        </label>
        <label>
          Action reason
          <input onChange={(event) => setReason(event.target.value)} value={reason} />
        </label>
        <div className="button-row">
          <button onClick={() => void refreshData()} type="button">Refresh my devices</button>
          <button disabled={!selected} onClick={() => void isolateSelected()} type="button">Isolate my device</button>
          <button className="secondary-action" disabled={!selected} onClick={() => void deisolateSelected()} type="button">De-isolate my device</button>
        </div>
        <PreviewTable headers={["Device ID", "Name", "Status"]} rows={devices.map((device) => [device.device_id, device.name, device.status])} />
      </section>
      <section className="panel">
        <h3>Register my device</h3>
        <form className="grid-form" onSubmit={(event) => void registerDevice(event)}>
          <label>
            Device ID
            <input onChange={(event) => setDeviceId(event.target.value)} value={deviceId} />
          </label>
          <label>
            Name
            <input onChange={(event) => setName(event.target.value)} value={name} />
          </label>
          <label>
            API Key
            <input onChange={(event) => setApiKey(event.target.value)} value={apiKey} />
          </label>
          <button type="submit">Register my device</button>
        </form>
        {result ? (
          <div style={{
            marginTop: "15px",
            padding: "12px",
            backgroundColor: "#1a4d6d",
            border: "1px solid #0f3460",
            borderRadius: "4px",
            color: "#4ade80"
          }}>
            <strong>✓ Device registered successfully!</strong>
            <p style={{ margin: "8px 0 0 0", fontSize: "14px" }}>Your device is now connected to the system and ready to send traffic data.</p>
          </div>
        ) : null}
      </section>
      <section className="panel">
        <h3>Live alerts for my devices</h3>
        <PreviewTable headers={["Device", "Rule", "Severity", "Message"]} rows={alerts.map((alert) => [alert.device_id, alert.rule_name, alert.severity, alert.message])} />
      </section>
    </section>
  );
}

function AdminDashboardPage({ apiGet, token }: { apiGet: <T>(path: string, authToken?: string) => Promise<T>; token: string }) {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [users, setUsers] = useState<UserItem[]>([]);

  useEffect(() => {
    void Promise.all([
      apiGet<SummaryResponse>("/dashboard/summary", token),
      apiGet<DeviceItem[]>("/devices", token),
      apiGet<UserItem[]> ("/admin/users", token),
    ])
      .then(([summaryData, deviceData, userData]) => {
        setSummary(summaryData);
        setDevices(deviceData);
        setUsers(userData);
      })
      .catch(() => {
        setSummary(null);
        setDevices([]);
        setUsers([]);
      });
  }, [apiGet, token]);

  return (
    <section className="stacked">
      <section className="hero-card">
        <p className="hero-tag">Admin Dashboard</p>
        <h2>Command and control overview</h2>
        <p>Monitor users and devices, then execute response actions from a single control plane.</p>
      </section>
      <section className="summary-grid">
        <Stat label="Devices" value={summary?.devices_total ?? 0} />
        <Stat label="Isolated" value={summary?.devices_isolated ?? 0} />
      </section>
      <section className="panel">
        <h3>Command center</h3>
        <div className="button-row">
          <Link className="cta-button" to="/devices">Manage devices</Link>
          <Link className="cta-button secondary" to="/alerts">Review alerts</Link>
          <Link className="cta-button secondary" to="/rules">Manage rules</Link>
          <Link className="cta-button secondary" to="/response">Run response actions</Link>
          <Link className="cta-button secondary" to="/backup">Export backup snapshot</Link>
          <Link className="cta-button secondary" to="/session">Setup MFA</Link>
        </div>
      </section>
      <section className="panel">
        <h3>Devices</h3>
        <PreviewTable headers={["Device ID", "Device Name", "Status"]} rows={devices.map((device) => [device.device_id, device.name, device.status])} />
      </section>
      <section className="panel">
        <h3>Users</h3>
        <PreviewTable
          headers={["Username", "Role", "Failed Attempts", "Locked"]}
          rows={users.map((user) => [user.username, user.role, String(user.failed_attempts), user.is_locked ? "Yes" : "No"])}
        />
      </section>
    </section>
  );
}

function DashboardPage({ apiGet, apiPost, token, role }: { apiGet: <T>(path: string, authToken?: string) => Promise<T>; apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string; role: string }) {
  return <AdminDashboardPage apiGet={apiGet} token={token} />;
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <article className="stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function PreviewTable({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((header) => <th key={header}>{header}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={`${row.join("-")}-${index}`}>
              {row.map((cell) => <td key={cell}>{cell}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DevicesPage({ apiGet, apiPost, token, role }: { apiGet: <T>(path: string, authToken?: string) => Promise<T>; apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string; role: string }) {
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [selected, setSelected] = useState("");
  const [reason, setReason] = useState("Manual admin action from portal");
  const [deviceId, setDeviceId] = useState("device-web-001");
  const [name, setName] = useState("Web Registered Device");
  const [apiKey, setApiKey] = useState("web-device-key-001");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  async function refreshDevices() {
    const data = await apiGet<DeviceItem[]>("/devices", token);
    setDevices(data);
    if (!selected && data.length > 0) {
      setSelected(data[0].device_id);
    }
  }

  async function registerDevice(event: FormEvent) {
    event.preventDefault();
    setResult(await apiPost("/devices/register", { device_id: deviceId, name, api_key: apiKey }, token));
    await refreshDevices();
  }

  async function isolateSelected() {
    if (!selected) return;
    setResult(await apiPost("/response/isolate-device", { device_id: selected, reason }, token));
    await refreshDevices();
  }

  async function deisolateSelected() {
    if (!selected) return;
    setResult(await apiPost("/response/deisolate-device", { device_id: selected, reason }, token));
    await refreshDevices();
  }

  async function isolateDevice(deviceIdToIsolate: string) {
    setSelected(deviceIdToIsolate);
    setResult(await apiPost<Record<string, unknown>>("/response/isolate-device", { device_id: deviceIdToIsolate, reason }, token));
    await refreshDevices();
  }

  async function deisolateDevice(deviceIdToDeisolate: string) {
    setSelected(deviceIdToDeisolate);
    setResult(await apiPost<Record<string, unknown>>("/response/deisolate-device", { device_id: deviceIdToDeisolate, reason }, token));
    await refreshDevices();
  }

  useEffect(() => {
    void refreshDevices();
  }, []);

  return (
    <section className="stacked">
      <section className="panel">
        <h2>Devices</h2>
        {role !== "admin" ? <p className="error">Only admins can register, isolate, or de-isolate devices.</p> : null}
        <p>Choose a device to isolate or de-isolate. Isolated devices are blocked from ingesting traffic.</p>
        <label>
          Selected device
          <select onChange={(event) => setSelected(event.target.value)} value={selected}>
            <option value="">Select a device</option>
            {devices.map((device) => (
              <option key={device.device_id} value={device.device_id}>
                {device.name} ({device.device_id}) - {device.status}
              </option>
            ))}
          </select>
        </label>
        <label>
          Action reason
          <input onChange={(event) => setReason(event.target.value)} value={reason} />
        </label>
        <div className="button-row">
          <button onClick={() => void refreshDevices()} type="button">Refresh devices</button>
          <button disabled={!selected || role !== "admin"} onClick={() => void isolateSelected()} type="button">Isolate selected</button>
          <button className="secondary-action" disabled={!selected || role !== "admin"} onClick={() => void deisolateSelected()} type="button">De-isolate selected</button>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Device ID</th>
                <th>Name</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr key={device.device_id}>
                  <td>{device.device_id}</td>
                  <td>{device.name}</td>
                  <td>{device.status}</td>
                  <td>
                    <div className="button-row compact-row">
                      <button onClick={() => setSelected(device.device_id)} type="button">Select</button>
                      <button disabled={device.status === "isolated" || role !== "admin"} onClick={() => void isolateDevice(device.device_id)} type="button">Isolate</button>
                      <button className="secondary-action" disabled={device.status !== "isolated" || role !== "admin"} onClick={() => void deisolateDevice(device.device_id)} type="button">De-isolate</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h3>Register a device</h3>
        <form className="grid-form" onSubmit={(event) => void registerDevice(event)}>
          <label>
            Device ID
            <input onChange={(event) => setDeviceId(event.target.value)} value={deviceId} />
          </label>
          <label>
            Name
            <input onChange={(event) => setName(event.target.value)} value={name} />
          </label>
          <label>
            API Key
            <input onChange={(event) => setApiKey(event.target.value)} value={apiKey} />
          </label>
          <button disabled={role !== "admin"} type="submit">Register device</button>
        </form>
        {result ? <pre>{JSON.stringify(result, null, 2)}</pre> : null}
      </section>
    </section>
  );
}

function AlertsPage({ apiGet, token }: { apiGet: <T>(path: string, authToken?: string) => Promise<T>; token: string }) {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  useEffect(() => {
    void apiGet<AlertItem[]>("/alerts", token).then(setAlerts).catch(() => setAlerts([]));
  }, [apiGet, token]);
  return (
    <section className="panel">
      <h2>Alerts</h2>
      <PreviewTable headers={["Device", "Rule", "Severity", "Message"]} rows={alerts.map((alert) => [alert.device_id, alert.rule_name, alert.severity, alert.message])} />
    </section>
  );
}

function RulesPage({
  apiGet,
  apiPost,
  apiPatch,
  token,
}: {
  apiGet: <T>(path: string, authToken?: string) => Promise<T>;
  apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>;
  apiPatch: <T>(path: string, body: unknown, authToken?: string) => Promise<T>;
  token: string;
}) {
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  const [newRuleName, setNewRuleName] = useState("request_frequency_custom");
  const [newDescription, setNewDescription] = useState("Detect high request rates for a device");
  const [newSeverity, setNewSeverity] = useState("high");
  const [newEnabled, setNewEnabled] = useState(true);
  const [newConfig, setNewConfig] = useState('{"type":"request_frequency","request_count_threshold":120,"burst_count_threshold":8,"window_seconds":60,"message":"Custom high frequency detected"}');

  const [editRuleName, setEditRuleName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editSeverity, setEditSeverity] = useState("high");
  const [editConfig, setEditConfig] = useState("{}");

  async function refreshRules() {
    const data = await apiGet<RuleItem[]>("/admin/rules", token);
    setRules(data);
    if (!selectedRuleId && data.length > 0) {
      setSelectedRuleId(data[0].rule_id);
    }
  }

  function loadRuleIntoEditor(ruleId: string) {
    setSelectedRuleId(ruleId);
    const rule = rules.find((item) => item.rule_id === ruleId);
    if (!rule) {
      return;
    }
    setEditRuleName(rule.rule_name);
    setEditDescription(rule.description);
    setEditSeverity(rule.severity);
    setEditConfig(JSON.stringify(rule.config, null, 2));
  }

  async function createRule(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const payload = {
        rule_name: newRuleName,
        description: newDescription,
        severity: newSeverity,
        enabled: newEnabled,
        config: JSON.parse(newConfig),
      };
      const response = await apiPost<RuleItem>("/admin/rules", payload, token);
      setResult(response as unknown as Record<string, unknown>);
      await refreshRules();
      loadRuleIntoEditor(response.rule_id);
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Failed to create rule";
      setError(message);
    }
  }

  async function updateRule(event: FormEvent) {
    event.preventDefault();
    if (!selectedRuleId) {
      return;
    }
    setError("");
    try {
      const payload = {
        rule_name: editRuleName,
        description: editDescription,
        severity: editSeverity,
        config: JSON.parse(editConfig),
      };
      const response = await apiPatch<RuleItem>(`/admin/rules/${selectedRuleId}`, payload, token);
      setResult(response as unknown as Record<string, unknown>);
      await refreshRules();
      loadRuleIntoEditor(selectedRuleId);
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Failed to update rule";
      setError(message);
    }
  }

  async function setEnabled(ruleId: string, enabled: boolean) {
    setError("");
    try {
      const path = enabled ? `/admin/rules/${ruleId}/enable` : `/admin/rules/${ruleId}/disable`;
      const response = await apiPost<RuleItem>(path, {}, token);
      setResult(response as unknown as Record<string, unknown>);
      await refreshRules();
      if (selectedRuleId === ruleId) {
        loadRuleIntoEditor(ruleId);
      }
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Failed to change rule status";
      setError(message);
    }
  }

  useEffect(() => {
    void refreshRules().catch(() => {
      setRules([]);
    });
    const timer = window.setInterval(() => {
      void refreshRules().catch(() => {
        setRules([]);
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [apiGet, token]);

  useEffect(() => {
    if (selectedRuleId) {
      loadRuleIntoEditor(selectedRuleId);
    }
  }, [selectedRuleId, rules]);

  return (
    <section className="stacked">
      <section className="panel">
        <h2>Rules</h2>
        <p>Create, update, enable, or disable detection rules directly from the admin portal.</p>
        {error ? <p className="error">{error}</p> : null}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Type</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.rule_id}>
                  <td>{rule.rule_name}</td>
                  <td>{rule.severity}</td>
                  <td>{rule.enabled ? "Enabled" : "Disabled"}</td>
                  <td>{String(rule.config.type || "unknown")}</td>
                  <td>
                    <div className="button-row compact-row">
                      <button onClick={() => loadRuleIntoEditor(rule.rule_id)} type="button">Edit</button>
                      <button
                        className="secondary-action"
                        onClick={() => void setEnabled(rule.rule_id, !rule.enabled)}
                        type="button"
                      >
                        {rule.enabled ? "Disable" : "Enable"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h3>Create rule</h3>
        <form className="grid-form" onSubmit={(event) => void createRule(event)}>
          <label>Rule name<input onChange={(event) => setNewRuleName(event.target.value)} value={newRuleName} /></label>
          <label>Description<input onChange={(event) => setNewDescription(event.target.value)} value={newDescription} /></label>
          <label>Severity<input onChange={(event) => setNewSeverity(event.target.value)} value={newSeverity} /></label>
          <label>
            Enabled
            <select onChange={(event) => setNewEnabled(event.target.value === "true")} value={String(newEnabled)}>
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
          <label>Config JSON<textarea onChange={(event) => setNewConfig(event.target.value)} rows={6} value={newConfig} /></label>
          <button type="submit">Create rule</button>
        </form>
      </section>

      <section className="panel">
        <h3>Update selected rule</h3>
        <form className="grid-form" onSubmit={(event) => void updateRule(event)}>
          <label>
            Selected rule
            <select onChange={(event) => loadRuleIntoEditor(event.target.value)} value={selectedRuleId}>
              <option value="">Select rule</option>
              {rules.map((rule) => (
                <option key={rule.rule_id} value={rule.rule_id}>{rule.rule_name}</option>
              ))}
            </select>
          </label>
          <label>Rule name<input onChange={(event) => setEditRuleName(event.target.value)} value={editRuleName} /></label>
          <label>Description<input onChange={(event) => setEditDescription(event.target.value)} value={editDescription} /></label>
          <label>Severity<input onChange={(event) => setEditSeverity(event.target.value)} value={editSeverity} /></label>
          <label>Config JSON<textarea onChange={(event) => setEditConfig(event.target.value)} rows={6} value={editConfig} /></label>
          <button disabled={!selectedRuleId} type="submit">Update rule</button>
        </form>
        {result ? (
          <div style={{
            marginTop: "15px",
            padding: "12px",
            backgroundColor: "#1a4d6d",
            border: "1px solid #0f3460",
            borderRadius: "4px",
            color: "#4ade80"
          }}>
            <strong>✓ Device registered successfully!</strong>
            <p style={{ margin: "8px 0 0 0", fontSize: "14px" }}>The device is now registered in the system and available for device management operations.</p>
          </div>
        ) : null}
      </section>
    </section>
  );
}

function TrafficPage({ apiPost, token }: { apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string }) {
  const [deviceId, setDeviceId] = useState("device-001");
  const [apiKey, setApiKey] = useState("device-key-001");
  const [destinationIp, setDestinationIp] = useState("8.8.8.8");
  const [destinationPort, setDestinationPort] = useState(443);
  const [requestCount, setRequestCount] = useState(120);
  const [payload, setPayload] = useState('{"query":"<script>alert(1)</script>"}');
  const [result, setResult] = useState<IngestResponse | null>(null);

  async function ingest(event: FormEvent) {
    event.preventDefault();
    setResult(
      await apiPost<IngestResponse>(
        "/devices/ingest",
        { destination_ip: destinationIp, destination_port: destinationPort, request_count: requestCount, payload: JSON.parse(payload) },
        undefined,
        { "X-Device-Id": deviceId, "X-Api-Key": apiKey },
      ),
    );
  }

  return (
    <section className="panel">
      <h2>Traffic ingestion</h2>
      <form className="grid-form" onSubmit={(event) => void ingest(event)}>
        <label>Device ID<input onChange={(event) => setDeviceId(event.target.value)} value={deviceId} /></label>
        <label>Device API Key<input onChange={(event) => setApiKey(event.target.value)} value={apiKey} /></label>
        <label>Destination IP<input onChange={(event) => setDestinationIp(event.target.value)} value={destinationIp} /></label>
        <label>Destination Port<input onChange={(event) => setDestinationPort(Number(event.target.value))} type="number" value={destinationPort} /></label>
        <label>Request Count<input onChange={(event) => setRequestCount(Number(event.target.value))} type="number" value={requestCount} /></label>
        <label>Payload JSON<textarea onChange={(event) => setPayload(event.target.value)} rows={4} value={payload} /></label>
        <button type="submit">Send traffic</button>
      </form>
      {result ? (
        <div style={{
          marginTop: "15px",
          padding: "12px",
          backgroundColor: "#1a4d6d",
          border: "1px solid #0f3460",
          borderRadius: "4px",
          color: "#4ade80"
        }}>
          <strong>✓ Traffic data sent successfully!</strong>
          <p style={{ margin: "8px 0 0 0", fontSize: "14px" }}>Your traffic packet has been received and processed by the system.</p>
        </div>
      ) : null}
    </section>
  );
}

function ResponsePage({ apiPost, token }: { apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string }) {
  const [deviceId, setDeviceId] = useState("device-001");
  const [reason, setReason] = useState("Manual response action from website");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  async function isolate(event: FormEvent) {
    event.preventDefault();
    setResult(await apiPost<Record<string, unknown>>("/response/isolate-device", { device_id: deviceId, reason }, token));
  }

  async function deisolate() {
    setResult(await apiPost<Record<string, unknown>>("/response/deisolate-device", { device_id: deviceId, reason }, token));
  }

  async function rbacCheck() {
    setResult(await apiPost<Record<string, unknown>>("/admin/rbac-check", {}, token));
  }

  return (
    <section className="panel">
      <h2>Response</h2>
      <form className="grid-form" onSubmit={(event) => void isolate(event)}>
        <label>Device ID<input onChange={(event) => setDeviceId(event.target.value)} value={deviceId} /></label>
        <label>Reason<input onChange={(event) => setReason(event.target.value)} value={reason} /></label>
        <div className="button-row">
          <button type="submit">Isolate device</button>
          <button className="secondary-action" onClick={() => void deisolate()} type="button">De-isolate device</button>
          <button onClick={() => void rbacCheck()} type="button">RBAC check</button>
        </div>
      </form>
      {result ? (
        <div style={{
          marginTop: "15px",
          padding: "12px",
          backgroundColor: "#1a4d6d",
          border: "1px solid #0f3460",
          borderRadius: "4px",
          color: "#4ade80"
        }}>
          <strong>✓ Role check completed!</strong>
          <p style={{ margin: "8px 0 0 0", fontSize: "14px" }}>Your access level has been verified.</p>
        </div>
      ) : null}
    </section>
  );
}

function SecurityPage({ apiPost, token }: { apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string }) {
  const [plain, setPlain] = useState("Password123!");
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  async function makeHash() {
    const response = await apiPost<{ password_hash: string }>("/security/hash-password", { password: plain });
    setHash(response.password_hash);
  }

  async function verifyPassword() {
    if (!hash) return;
    setResult(await apiPost<Record<string, unknown>>("/security/verify-password", { password: plain, password_hash: hash }));
  }

  async function verifyToken() {
    setResult(await apiPost<Record<string, unknown>>("/security/verify-token", { token }));
  }

  return (
    <section className="panel">
      <h2>Security tools</h2>
      <label>
        Plain password
        <input onChange={(event) => setPlain(event.target.value)} value={plain} />
      </label>
      <div className="button-row">
        <button onClick={() => void makeHash()} type="button">Hash password</button>
        <button disabled={!hash} onClick={() => void verifyPassword()} type="button">Verify password</button>
        <button disabled={!token} onClick={() => void verifyToken()} type="button">Verify token</button>
      </div>
      {hash ? (
        <div style={{
          marginTop: "15px",
          padding: "12px",
          backgroundColor: "#1a4d6d",
          border: "1px solid #0f3460",
          borderRadius: "4px",
          color: "#4ade80"
        }}>
          <strong>✓ Password hashed successfully!</strong>
          <p style={{ margin: "8px 0 0 0", fontSize: "14px" }}>Now you can verify if the password matches this hash.</p>
        </div>
      ) : null}
      {result ? (
        <div style={{
          marginTop: "15px",
          padding: "12px",
          backgroundColor: "#1a4d6d",
          border: "1px solid #0f3460",
          borderRadius: "4px",
          color: result.match ? "#4ade80" : "#ef4444"
        }}>
          <strong>{result.match ? "✓ Password matches!" : "✗ Password does not match"}</strong>
        </div>
      ) : null}
    </section>
  );
}

function BackupPage({ apiGet, token }: { apiGet: <T>(path: string, authToken?: string) => Promise<T>; token: string }) {
  const [snapshot, setSnapshot] = useState<BackupSnapshot | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const data = await apiGet<BackupSnapshot>("/admin/backup/snapshot", token);
      setSnapshot(data);
    } catch (error) {
      console.error("Failed to load backup snapshot:", error);
      alert("Failed to load backup snapshot");
    } finally {
      setLoading(false);
    }
  }

  const downloadJSON = () => {
    if (!snapshot) return;
    const json = JSON.stringify(snapshot, null, 2);
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(json, `backup_${timestamp}.json`, "application/json");
  };

  const downloadCSV = (dataKey: keyof Omit<BackupSnapshot, 'exported_at'>, title: string) => {
    if (!snapshot) return;
    const data = snapshot[dataKey] as Array<Record<string, unknown>>;
    const csv = convertToCsv(data);
    if (!csv) {
      alert(`No ${title} data to download`);
      return;
    }
    const timestamp = new Date().toISOString().split('T')[0];
    downloadFile(csv, `backup_${title}_${timestamp}.csv`, "text/csv");
  };

  const downloadAllCSV = () => {
    if (!snapshot) return;
    const timestamp = new Date().toISOString().split('T')[0];
    
    const sections: Array<{ key: keyof Omit<BackupSnapshot, 'exported_at'>; title: string }> = [
      { key: "users", title: "Users" },
      { key: "devices", title: "Devices" },
      { key: "traffic_logs", title: "Traffic Logs" },
      { key: "alerts", title: "Alerts" },
      { key: "audit_logs", title: "Audit Logs" },
      { key: "rules", title: "Rules" }
    ];

    let allCsv = sections.map(({ key, title }) => {
      const data = snapshot[key] as Array<Record<string, unknown>>;
      const csv = convertToCsv(data);
      return csv ? `${title}\n${csv}` : "";
    }).filter(Boolean).join("\n\n");

    downloadFile(allCsv, `backup_all_${timestamp}.csv`, "text/csv");
  };

  return (
    <section className="panel">
      <h2>📦 System Backup & Export</h2>
      
      <div style={{ marginBottom: "20px", display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <button 
          onClick={() => void load()} 
          type="button"
          disabled={loading}
          style={{
            padding: "10px 16px",
            backgroundColor: "#e94560",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: loading ? "not-allowed" : "pointer",
            fontWeight: "bold",
            opacity: loading ? 0.6 : 1
          }}
        >
          {loading ? "Loading..." : "📥 Export Snapshot"}
        </button>
        
        {snapshot && (
          <>
            <button 
              onClick={downloadJSON}
              type="button"
              title="Download backup as JSON"
              style={{
                padding: "10px 16px",
                backgroundColor: "#4ade80",
                color: "#000",
                border: "none",
                borderRadius: "4px",
                cursor: "pointer",
                fontWeight: "bold"
              }}
            >
              📄 JSON
            </button>
            
            <button 
              onClick={() => downloadAllCSV()}
              type="button"
              title="Download all data as CSV"
              style={{
                padding: "10px 16px",
                backgroundColor: "#60a5fa",
                color: "#000",
                border: "none",
                borderRadius: "4px",
                cursor: "pointer",
                fontWeight: "bold"
              }}
            >
              📊 All CSV
            </button>

            <div style={{ fontSize: "12px", color: "#aaa", padding: "10px 0" }}>
              <strong style={{ color: "#e0e0e0" }}>Individual Downloads:</strong>
              <div style={{ marginTop: "8px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                <button onClick={() => downloadCSV("users", "Users")} type="button" style={{ padding: "6px 12px", fontSize: "12px", backgroundColor: "#94a3b8", color: "#000", border: "none", borderRadius: "3px", cursor: "pointer" }}>Users CSV</button>
                <button onClick={() => downloadCSV("devices", "Devices")} type="button" style={{ padding: "6px 12px", fontSize: "12px", backgroundColor: "#94a3b8", color: "#000", border: "none", borderRadius: "3px", cursor: "pointer" }}>Devices CSV</button>
                <button onClick={() => downloadCSV("traffic_logs", "Traffic_Logs")} type="button" style={{ padding: "6px 12px", fontSize: "12px", backgroundColor: "#94a3b8", color: "#000", border: "none", borderRadius: "3px", cursor: "pointer" }}>Traffic Logs CSV</button>
                <button onClick={() => downloadCSV("alerts", "Alerts")} type="button" style={{ padding: "6px 12px", fontSize: "12px", backgroundColor: "#94a3b8", color: "#000", border: "none", borderRadius: "3px", cursor: "pointer" }}>Alerts CSV</button>
                <button onClick={() => downloadCSV("audit_logs", "Audit_Logs")} type="button" style={{ padding: "6px 12px", fontSize: "12px", backgroundColor: "#94a3b8", color: "#000", border: "none", borderRadius: "3px", cursor: "pointer" }}>Audit Logs CSV</button>
                <button onClick={() => downloadCSV("rules", "Rules")} type="button" style={{ padding: "6px 12px", fontSize: "12px", backgroundColor: "#94a3b8", color: "#000", border: "none", borderRadius: "3px", cursor: "pointer" }}>Rules CSV</button>
              </div>
            </div>
          </>
        )}
      </div>

      {snapshot && (
        <div style={{ 
          backgroundColor: "#0f3460",
          padding: "20px",
          borderRadius: "8px",
          marginBottom: "20px",
          border: "1px solid #1a4d6d"
        }}>
          <p style={{ color: "#e0e0e0", margin: "0" }}>
            <strong style={{ color: "#e94560" }}>Exported at:</strong> {new Date(snapshot.exported_at).toLocaleString()}
          </p>
          <p style={{ color: "#e0e0e0", margin: "8px 0 0 0" }}>
            <strong style={{ color: "#e94560" }}>Records:</strong> Users: <span style={{ color: "#4ade80" }}>{snapshot.users.length}</span> | Devices: <span style={{ color: "#4ade80" }}>{snapshot.devices.length}</span> | Traffic Logs: <span style={{ color: "#4ade80" }}>{snapshot.traffic_logs.length}</span> | Alerts: <span style={{ color: "#4ade80" }}>{snapshot.alerts.length}</span> | Audit Logs: <span style={{ color: "#4ade80" }}>{snapshot.audit_logs.length}</span> | Rules: <span style={{ color: "#4ade80" }}>{snapshot.rules.length}</span>
          </p>
        </div>
      )}

      {snapshot && (
        <div>
          {renderDataTable("Users", snapshot.users)}
          {renderDataTable("Devices", snapshot.devices)}
          {renderDataTable("Traffic Logs", snapshot.traffic_logs)}
          {renderDataTable("Alerts", snapshot.alerts)}
          {renderDataTable("Audit Logs", snapshot.audit_logs)}
          {renderDataTable("Rules", snapshot.rules)}
        </div>
      )}
    </section>
  );
}

function LoginPage({ login, mfaPending, validateMfa }: { login: (username: string, password: string) => Promise<void>; mfaPending: string; validateMfa: (code: string) => Promise<void> }) {
  return <AuthPage mode="login" mfaPending={mfaPending} onSubmit={login} onValidateMfa={validateMfa} />;
}

function RegisterPage({ register }: { register: (username: string, password: string) => Promise<void> }) {
  return <AuthPage mode="register" onSubmit={register} />;
}

function SessionPage({ apiPost, token, refreshToken, onLogout }: { apiPost: <T>(path: string, body: unknown, authToken?: string, extraHeaders?: Record<string, string>) => Promise<T>; token: string; refreshToken: string; onLogout: () => void }) {
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaSetupData, setMfaSetupData] = useState<{ secret?: string; provisioning_uri?: string } | null>(null);
  const [mfaStep, setMfaStep] = useState<"idle" | "setup" | "verify">("idle");

  async function setupMfa() {
    if (!token) return;
    try {
      const response = await apiPost<{ secret: string; provisioning_uri: string }>("/auth/mfa/setup", {}, token);
      setMfaSetupData(response);
      setMfaStep("setup");
      setMfaCode("");
      setResult(null);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to setup MFA";
      setResult({ error: message });
    }
  }

  async function verifyMfa() {
    if (!token || mfaCode.length !== 6) return;
    try {
      const response = await apiPost<Record<string, unknown>>("/auth/mfa/verify", { code: mfaCode }, token);
      setResult(response);
      setMfaStep("idle");
      setMfaSetupData(null);
      setMfaCode("");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to verify MFA";
      setResult({ error: message });
    }
  }

  async function disableMfa() {
    if (!token || mfaCode.length !== 6) return;
    try {
      const response = await apiPost<Record<string, unknown>>("/auth/mfa/disable", { code: mfaCode }, token);
      setResult(response);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to disable MFA";
      setResult({ error: message });
    }
  }

  async function cancelSetup() {
    setMfaStep("idle");
    setMfaSetupData(null);
    setMfaCode("");
    setResult(null);
  }

  async function refreshSession() {
    if (!refreshToken) return;
    setResult(await apiPost<Record<string, unknown>>("/auth/refresh", { refresh_token: refreshToken }));
  }

  async function logoutServer() {
    if (!refreshToken) return;
    setResult(await apiPost<Record<string, unknown>>("/auth/logout", { refresh_token: refreshToken }));
    onLogout();
  }

  async function rbacCheck() {
    if (!token) return;
    setResult(await apiPost<Record<string, unknown>>("/admin/rbac-check", {}, token));
  }

  return (
    <section className="panel">
      <h2>Session</h2>
      <p>Use refresh, logout, and role checks here.</p>
      <div className="button-row">
        <button disabled={!refreshToken} onClick={() => void refreshSession()} type="button">Refresh session</button>
        <button disabled={!refreshToken} onClick={() => void logoutServer()} type="button">Logout server-side</button>
        <button disabled={!token} onClick={() => void rbacCheck()} type="button">Verify admin role</button>
      </div>
      <h3 style={{ marginTop: "16px" }}>MFA Setup</h3>
      
      {mfaStep === "idle" ? (
        <>
          <p>Enable two-factor authentication for your admin account.</p>
          <div className="button-row">
            <button disabled={!token} onClick={() => void setupMfa()} type="button">Setup MFA</button>
          </div>
        </>
      ) : null}

      {mfaStep === "setup" && mfaSetupData?.provisioning_uri ? (
        <div style={{
          marginTop: "20px",
          padding: "20px",
          backgroundColor: "#0f3460",
          border: "2px solid #e94560",
          borderRadius: "8px"
        }}>
          <h4 style={{ color: "#e94560", marginTop: 0 }}>Step 1: Scan QR Code</h4>
          <p style={{ fontSize: "14px", color: "#e0e0e0" }}>
            Open an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.) and scan this QR code:
          </p>
          <div style={{
            backgroundColor: "#fff",
            padding: "12px",
            borderRadius: "4px",
            display: "inline-block",
            marginBottom: "20px"
          }}>
            <QRCodeSVG 
              value={mfaSetupData.provisioning_uri}
              size={256}
              level="H"
              includeMargin={true}
            />
          </div>
          <p style={{ fontSize: "12px", color: "#aaa", marginTop: "12px" }}>
            <strong>Can't scan?</strong> Enter this code manually in your authenticator app:
          </p>
          <code style={{
            display: "block",
            padding: "10px",
            backgroundColor: "#1a3a52",
            borderRadius: "4px",
            marginTop: "8px",
            fontSize: "14px",
            wordBreak: "break-all",
            color: "#4ade80"
          }}>
            {mfaSetupData.secret}
          </code>

          <h4 style={{ color: "#e94560", marginTop: "20px" }}>Step 2: Enter 6-digit Code</h4>
          <p style={{ fontSize: "14px", color: "#e0e0e0" }}>
            Once you've scanned the QR code, enter the 6-digit code from your authenticator app:
          </p>
          <div style={{
            display: "flex",
            gap: "10px",
            alignItems: "center",
            marginTop: "12px",
            flexWrap: "wrap"
          }}>
            <input
              inputMode="numeric"
              maxLength={6}
              onChange={(event) => setMfaCode(event.target.value)}
              placeholder="123456"
              style={{
                padding: "10px",
                borderRadius: "4px",
                border: "1px solid #1a4d6d",
                backgroundColor: "#1a3a52",
                color: "#fff",
                fontSize: "16px",
                width: "120px"
              }}
              value={mfaCode}
            />
            <button 
              disabled={mfaCode.length !== 6}
              onClick={() => void verifyMfa()} 
              type="button"
              style={{
                padding: "10px 16px",
                backgroundColor: "#4ade80",
                color: "#000",
                border: "none",
                borderRadius: "4px",
                cursor: mfaCode.length === 6 ? "pointer" : "not-allowed",
                fontWeight: "bold",
                opacity: mfaCode.length === 6 ? 1 : 0.5
              }}
            >
              Verify & Enable MFA
            </button>
            <button 
              onClick={() => void cancelSetup()} 
              type="button"
              style={{
                padding: "10px 16px",
                backgroundColor: "#ef4444",
                color: "#fff",
                border: "none",
                borderRadius: "4px",
                cursor: "pointer"
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {mfaStep === "idle" ? (
        <>
          <h3 style={{ marginTop: "20px" }}>Disable MFA</h3>
          <p>If you need to disable MFA, enter your 6-digit authenticator code:</p>
          <div style={{
            display: "flex",
            gap: "10px",
            alignItems: "center",
            flexWrap: "wrap"
          }}>
            <input
              inputMode="numeric"
              maxLength={6}
              onChange={(event) => setMfaCode(event.target.value)}
              placeholder="Enter 6-digit MFA code"
              style={{
                padding: "10px",
                borderRadius: "4px",
                border: "1px solid #1a4d6d",
                backgroundColor: "#1a3a52",
                color: "#fff",
                fontSize: "14px",
                maxWidth: "240px"
              }}
              value={mfaCode}
            />
            <button disabled={!token || mfaCode.length !== 6} onClick={() => void disableMfa()} type="button">Disable MFA</button>
          </div>
        </>
      ) : null}

      {result ? (
        <div style={{
          marginTop: "15px",
          padding: "12px",
          backgroundColor: result.error ? "#4d1a1a" : "#1a4d6d",
          border: `1px solid ${result.error ? "#ef4444" : "#0f3460"}`,
          borderRadius: "4px",
          color: result.error ? "#ef4444" : "#4ade80"
        }}>
          <strong>{result.error ? "✗ Error" : "✓ Success"}!</strong>
          <p style={{ margin: "8px 0 0 0", fontSize: "14px" }}>
            {result.error ? (result.error as string) : "Your MFA settings have been updated successfully."}
          </p>
        </div>
      ) : null}
    </section>
  );
}

function NotFoundPage() {
  return (
    <section className="hero-card not-found-card">
      <p className="hero-tag">404</p>
      <h2>Page not found</h2>
      <p>The page you requested does not exist.</p>
      <Link className="cta-button" to="/">Go home</Link>
    </section>
  );
}

function App() {
  const api = useApiClient();
  const hasStatus = Boolean(api.status || api.error);

  return (
    <AppShell logout={api.logout} role={api.role} token={api.token}>
      {hasStatus ? (
        <div className="status-strip">
          {api.status ? <span>{api.status}</span> : null}
          {api.error ? <span className="error">{api.error}</span> : null}
        </div>
      ) : null}
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage login={api.login} mfaPending={api.mfaPending} validateMfa={api.validateMfa} />} />
        <Route path="/register" element={<RegisterPage register={api.register} />} />
        <Route path="/health" element={<RequireAdmin token={api.token} role={api.role}><HealthPage apiGet={api.apiGet} /></RequireAdmin>} />
        <Route path="/dashboard" element={<RequireAuth token={api.token}><DashboardPage apiGet={api.apiGet} apiPost={api.apiPost} role={api.role} token={api.token} /></RequireAuth>} />
        <Route path="/session" element={<RequireAdmin token={api.token} role={api.role}><SessionPage apiPost={api.apiPost} token={api.token} refreshToken={api.refreshToken} onLogout={api.logout} /></RequireAdmin>} />
        <Route path="/devices" element={<RequireAdmin token={api.token} role={api.role}><DevicesPage apiGet={api.apiGet} apiPost={api.apiPost} role={api.role} token={api.token} /></RequireAdmin>} />
        <Route path="/alerts" element={<RequireAdmin token={api.token} role={api.role}><AlertsPage apiGet={api.apiGet} token={api.token} /></RequireAdmin>} />
        <Route path="/rules" element={<RequireAdmin token={api.token} role={api.role}><RulesPage apiGet={api.apiGet} apiPost={api.apiPost} apiPatch={api.apiPatch} token={api.token} /></RequireAdmin>} />
        <Route path="/traffic" element={<RequireAuth token={api.token}><TrafficPage apiPost={api.apiPost} token={api.token} /></RequireAuth>} />
        <Route path="/response" element={<RequireAdmin token={api.token} role={api.role}><ResponsePage apiPost={api.apiPost} token={api.token} /></RequireAdmin>} />
        <Route path="/security" element={<RequireAuth token={api.token}><SecurityPage apiPost={api.apiPost} token={api.token} /></RequireAuth>} />
        <Route path="/backup" element={<RequireAdmin token={api.token} role={api.role}><BackupPage apiGet={api.apiGet} token={api.token} /></RequireAdmin>} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AppShell>
  );
}

export default App;