import React, { useEffect, useState } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { apiRequest } from "./api/client";
import { Layout } from "./components/Layout";
import { StatusBadge } from "./components/StatusBadge";
import { AuditLogsPage } from "./pages/AuditLogsPage";
import { DevicesPage } from "./pages/DevicesPage";
import { KeysPage } from "./pages/KeysPage";
import { MessagesPage } from "./pages/MessagesPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RecoveryBackupsPage } from "./pages/RecoveryBackupsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { ThreatDetectionPage } from "./pages/ThreatDetectionPage";
import { UsersPage } from "./pages/UsersPage";
import { AuthUser, DemoAccount, NavTab, ServiceNode } from "./types";

const SYNTHETIC_DEMO_HINTS: Record<string, string> = {
  "alice.admin": "AdminPass#2026!",
  "bob.eng": "EmpPass#2026!",
  "carol.viewer": "ViewPass#2026!",
};

export function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("tg_token"));
  const [user, setUser] = useState<AuthUser | null>(() => {
    const raw = localStorage.getItem("tg_user");
    return raw ? JSON.parse(raw) : null;
  });
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [nodes, setNodes] = useState<ServiceNode[]>([]);

  // Login state
  const [demoAccounts, setDemoAccounts] = useState<DemoAccount[]>([]);
  const [username, setUsername] = useState("alice.admin");
  const [password, setPassword] = useState("AdminPass#2026!");
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [backendStatus, setBackendStatus] = useState<string>("checking...");

  const loadPublic = async () => {
    try {
      const [h, accs] = await Promise.all([
        apiRequest<any>("/api/health"),
        apiRequest<DemoAccount[]>("/api/auth/demo-accounts"),
      ]);
      setBackendStatus(
        h.pqc_available
          ? `Online • ${h.algorithms.kem} + ${h.algorithms.signature}`
          : "PQC Library Unavailable"
      );
      setDemoAccounts(accs);
    } catch {
      setBackendStatus("Backend Offline (Start FastAPI on :8000)");
    }
  };

  const refreshNodes = async () => {
    if (!token) return;
    try {
      const n = await apiRequest<ServiceNode[]>("/api/nodes", {
        token,
        deviceId: user?.device_id ?? null,
      });
      setNodes(n);
    } catch {
      // Ignored if session revoked; individual pages surface the exact 403
    }
  };

  useEffect(() => {
    loadPublic();
  }, []);

  useEffect(() => {
    if (token) {
      refreshNodes();
    }
  }, [token]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    try {
      const res = await apiRequest<{ access_token: string; user: AuthUser }>("/api/auth/login", {
        method: "POST",
        body: {
          username,
          password,
          device_id: selectedDeviceId || null,
        },
      });
      localStorage.setItem("tg_token", res.access_token);
      localStorage.setItem("tg_user", JSON.stringify(res.user));
      setToken(res.access_token);
      setUser(res.user);
      setActiveTab("overview");
    } catch (err: any) {
      setLoginError(err.message);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("tg_token");
    localStorage.removeItem("tg_user");
    setToken(null);
    setUser(null);
    setNodes([]);
    loadPublic();
  };

  const selectDemoAccount = (acc: DemoAccount) => {
    setUsername(acc.username);
    setPassword(SYNTHETIC_DEMO_HINTS[acc.username] ?? "");
    const firstActive = acc.devices.find((d) => d.status === "ACTIVE");
    setSelectedDeviceId(firstActive?.device_id ?? acc.devices[0]?.device_id ?? "");
    setLoginError(null);
  };

  if (!token || !user) {
    const matchingAccount = demoAccounts.find((a) => a.username === username);
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="max-w-3xl w-full grid grid-cols-1 md:grid-cols-2 gap-6 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white">TrustGuard</h1>
                <p className="text-xs text-cyan-400 font-mono">Post-Quantum Zero Trust Platform</p>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
              Engine Status: <span className="text-emerald-300">{backendStatus}</span>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Synthetic Hackathon Identities
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {demoAccounts.map((acc) => (
                  <button
                    key={acc.user_id}
                    type="button"
                    onClick={() => selectDemoAccount(acc)}
                    className={`w-full text-left p-2.5 rounded-lg border transition-colors ${
                      username === acc.username
                        ? "bg-cyan-500/10 border-cyan-500/40"
                        : "bg-slate-950 border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white">{acc.username}</span>
                      <StatusBadge value={acc.role} />
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">{acc.full_name}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <form onSubmit={handleLogin} className="space-y-4 flex flex-col justify-center">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              Zero-Trust Authentication
            </div>

            {loginError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {loginError}
              </div>
            )}

            <div>
              <label className="block text-xs text-slate-400 mb-1">Username</label>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Bind Endpoint Device</label>
              <select
                value={selectedDeviceId}
                onChange={(e) => setSelectedDeviceId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
              >
                <option value="">Auto-select active device</option>
                {matchingAccount?.devices.map((d) => (
                  <option key={d.device_id} value={d.device_id}>
                    {d.device_id} — {d.device_name} ({d.status})
                  </option>
                ))}
              </select>
            </div>

            <button
              type="submit"
              className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold"
            >
              Authenticate & Bind Device
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <Layout
      activeTab={activeTab}
      onSelectTab={setActiveTab}
      user={user}
      nodes={nodes}
      onLogout={handleLogout}
    >
      {activeTab === "overview" && (
        <OverviewPage token={token} deviceId={user.device_id} onRefreshNodes={refreshNodes} />
      )}
      {activeTab === "users" && <UsersPage token={token} deviceId={user.device_id} />}
      {activeTab === "keys" && <KeysPage token={token} deviceId={user.device_id} />}
      {activeTab === "messages" && (
        <MessagesPage token={token} deviceId={user.device_id} currentUserId={user.user_id} />
      )}
      {activeTab === "devices" && (
        <DevicesPage token={token} deviceId={user.device_id} onRefreshNodes={refreshNodes} />
      )}
      {activeTab === "threats" && <ThreatDetectionPage token={token} deviceId={user.device_id} />}
      {activeTab === "audit" && <AuditLogsPage token={token} deviceId={user.device_id} />}
      {activeTab === "backups" && <RecoveryBackupsPage token={token} deviceId={user.device_id} />}
      {activeTab === "settings" && (
        <SettingsPage token={token} deviceId={user.device_id} onRefreshNodes={refreshNodes} />
      )}
    </Layout>
  );
}

export default App;
