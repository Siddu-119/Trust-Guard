import React, { useEffect, useState } from "react";
import { ShieldCheck, Trash2, UserPlus } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { AccessDecision, DeviceRecord, Role, UserRecord } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
}

export const UsersPage: React.FC<Props> = ({ token, deviceId }) => {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [decisions, setDecisions] = useState<AccessDecision[]>([]);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  // Register user form
  const [username, setUsername] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState<Role>("Employee");
  const [password, setPassword] = useState("TestPass#2026!");
  const [initDevice, setInitDevice] = useState("");

  // Permission override form
  const [permUserId, setPermUserId] = useState("usr-bob");
  const [permResource, setPermResource] = useState("vault-docs");
  const [permAction, setPermAction] = useState("write");
  const [permAllowed, setPermAllowed] = useState(true);

  // Access evaluation form
  const [chkUserId, setChkUserId] = useState("usr-bob");
  const [chkDeviceId, setChkDeviceId] = useState("dev-bob-01");
  const [chkSource, setChkSource] = useState("node-a");
  const [chkDest, setChkDest] = useState("node-b");
  const [chkResource, setChkResource] = useState("messages");
  const [chkAction, setChkAction] = useState("write");

  const loadAll = async () => {
    try {
      const [u, d, dec] = await Promise.all([
        apiRequest<UserRecord[]>("/api/users", { token, deviceId }),
        apiRequest<DeviceRecord[]>("/api/devices", { token, deviceId }),
        apiRequest<AccessDecision[]>("/api/access/decisions?limit=20", { token, deviceId }),
      ]);
      setUsers(u);
      setDevices(d);
      setDecisions(dec);
      if (u.length > 0 && !u.some((usr) => usr.user_id === permUserId)) {
        setPermUserId(u[0].user_id);
      }
      if (u.length > 0 && !u.some((usr) => usr.user_id === chkUserId)) {
        setChkUserId(u[0].user_id);
        const dev = d.find((dv) => dv.owner_id === u[0].user_id);
        setChkDeviceId(dev ? dev.device_id : "");
      }
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadAll();
  }, [token, deviceId]);

  const handleRegisterUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const created = await apiRequest<any>("/api/users", {
        method: "POST",
        token,
        deviceId,
        body: {
          username,
          full_name: fullName,
          role,
          password,
          initial_device_name: initDevice || null,
        },
      });
      setFeedback({
        type: "ok",
        msg: `Registered '${created.username}' (${created.role}) with ML-DSA-65 signing key ${created.signing_key_id}.`,
      });
      setUsername("");
      setFullName("");
      setInitDevice("");
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleRoleChange = async (userId: string, newRole: Role) => {
    setFeedback(null);
    try {
      await apiRequest(`/api/users/${userId}/role`, {
        method: "PATCH",
        token,
        deviceId,
        body: { role: newRole },
      });
      setFeedback({ type: "ok", msg: `Updated role for ${userId} to ${newRole}.` });
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleDeleteUser = async (targetUser: UserRecord) => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>(`/api/users/${targetUser.user_id}`, {
        method: "DELETE",
        token,
        deviceId,
      });
      setFeedback({
        type: "ok",
        msg: `Deleted ${res.deleted_role} '${res.deleted_username}' and revoked ${res.keys_revoked} key(s).`,
      });
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleSetPermission = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      await apiRequest(`/api/users/${permUserId}/permissions`, {
        method: "POST",
        token,
        deviceId,
        body: { resource: permResource, action: permAction, allowed: permAllowed },
      });
      setFeedback({
        type: "ok",
        msg: `Policy updated: ${permUserId} ${permAllowed ? "ALLOW" : "DENY"} ${permResource}:${permAction}.`,
      });
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleCheckAccess = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const res = await apiRequest<any>("/api/access/check", {
        method: "POST",
        token,
        deviceId,
        body: {
          user_id: chkUserId,
          device_id: chkDeviceId || null,
          source_service: chkSource,
          destination_service: chkDest,
          resource: chkResource,
          action: chkAction,
        },
      });
      setFeedback({
        type: res.decision === "ALLOW" ? "ok" : "err",
        msg: `Zero-Trust Decision: ${res.decision} — ${res.reason}`,
      });
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Users, Identities & Zero-Trust Access Control</h1>
        <p className="text-sm text-slate-400">
          Server-side RBAC, explicit resource permissions, device binding, and decision logging.
        </p>
      </div>

      {feedback && (
        <div
          className={`p-3 rounded-lg border text-sm ${
            feedback.type === "ok"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-rose-500/10 border-rose-500/30 text-rose-300"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* Forms Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Register Synthetic User */}
        <form
          onSubmit={handleRegisterUser}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <UserPlus className="w-4 h-4 text-cyan-400" />
            Register Synthetic User (Admin)
          </div>
          <input
            type="text"
            required
            placeholder="Username (e.g. dave.ops)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
          />
          <input
            type="text"
            required
            placeholder="Full Name"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
          />
          <div className="grid grid-cols-2 gap-2">
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              <option value="Admin">Admin</option>
              <option value="Employee">Employee</option>
              <option value="Viewer">Viewer</option>
            </select>
            <input
              type="password"
              required
              placeholder="Password (min 8)"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <input
            type="text"
            placeholder="Initial Device Name (optional)"
            value={initDevice}
            onChange={(e) => setInitDevice(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
          />
          <button
            type="submit"
            className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
          >
            Register & Provision ML-DSA Key
          </button>
        </form>

        {/* Assign Resource Permission */}
        <form
          onSubmit={handleSetPermission}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="text-sm font-semibold text-white">Assign Resource Permission (Admin)</div>
          <select
            value={permUserId}
            onChange={(e) => setPermUserId(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
          >
            {users.map((u) => (
              <option key={u.user_id} value={u.user_id}>
                {u.username} ({u.role})
              </option>
            ))}
          </select>
          <div className="grid grid-cols-2 gap-2">
            <select
              value={permResource}
              onChange={(e) => setPermResource(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              <option value="vault-docs">vault-docs</option>
              <option value="messages">messages</option>
              <option value="keys">keys</option>
              <option value="devices">devices</option>
              <option value="backups">backups</option>
              <option value="audit">audit</option>
            </select>
            <select
              value={permAction}
              onChange={(e) => setPermAction(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              <option value="read">read</option>
              <option value="write">write</option>
              <option value="send">send</option>
              <option value="rotate">rotate</option>
              <option value="revoke">revoke</option>
            </select>
          </div>
          <select
            value={permAllowed ? "allow" : "deny"}
            onChange={(e) => setPermAllowed(e.target.value === "allow")}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
          >
            <option value="allow">ALLOW Override</option>
            <option value="deny">DENY Override</option>
          </select>
          <button
            type="submit"
            className="w-full py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium"
          >
            Save Policy Override
          </button>
        </form>

        {/* Zero-Trust Access Check */}
        <form
          onSubmit={handleCheckAccess}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Evaluate Zero-Trust Access
          </div>
          <div className="grid grid-cols-2 gap-2">
            <select
              value={chkUserId}
              onChange={(e) => {
                const nextUid = e.target.value;
                setChkUserId(nextUid);
                const firstDev = devices.find((d) => d.owner_id === nextUid);
                setChkDeviceId(firstDev ? firstDev.device_id : "");
              }}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              {users.map((u) => (
                <option key={u.user_id} value={u.user_id}>
                  {u.username}
                </option>
              ))}
            </select>
            <select
              value={chkDeviceId}
              onChange={(e) => setChkDeviceId(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              <option value="">No device</option>
              {devices
                .filter((d) => d.owner_id === chkUserId)
                .map((d) => (
                  <option key={d.device_id} value={d.device_id}>
                    {d.device_id} ({d.status})
                  </option>
                ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <select
              value={chkSource}
              onChange={(e) => setChkSource(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              <option value="client">from: client</option>
              <option value="node-a">from: node-a</option>
              <option value="node-b">from: node-b</option>
              <option value="node-c">from: node-c</option>
            </select>
            <select
              value={chkDest}
              onChange={(e) => setChkDest(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              <option value="node-a">to: node-a</option>
              <option value="node-b">to: node-b</option>
              <option value="node-c">to: node-c</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <input
              type="text"
              value={chkResource}
              onChange={(e) => setChkResource(e.target.value)}
              placeholder="Resource"
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
            <input
              type="text"
              value={chkAction}
              onChange={(e) => setChkAction(e.target.value)}
              placeholder="Action"
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <button
            type="submit"
            className="w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium"
          >
            Run Access Decision
          </button>
        </form>
      </div>

      {/* Users Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-white">
          Registered Identities & Explicit Resource Permissions
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Role (Change)</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Explicit Resource Overrides</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {users.map((u) => (
                <tr key={u.user_id} className="hover:bg-slate-800/40">
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{u.username}</div>
                    <div className="text-slate-400">{u.full_name}</div>
                    <div className="text-slate-500 font-mono">{u.user_id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <StatusBadge value={u.role} />
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.user_id, e.target.value as Role)}
                        className="px-2 py-1 rounded bg-slate-950 border border-slate-700 text-slate-200 text-xs"
                      >
                        <option value="Admin">Admin</option>
                        <option value="Employee">Employee</option>
                        <option value="Viewer">Viewer</option>
                      </select>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge value={u.status} />
                  </td>
                  <td className="px-4 py-3">
                    {u.permissions.length === 0 ? (
                      <span className="text-slate-500">Default RBAC matrix</span>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {u.permissions.map((p) => (
                          <span
                            key={p.perm_id}
                            className={`px-2 py-0.5 rounded font-mono border ${
                              p.allowed
                                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                                : "bg-rose-500/10 border-rose-500/30 text-rose-300"
                            }`}
                          >
                            {p.resource}:{p.action}={p.allowed ? "ALLOW" : "DENY"}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {u.role !== "Admin" ? (
                      <button
                        type="button"
                        onClick={() => handleDeleteUser(u)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-600/20 hover:bg-rose-600/35 text-rose-300 border border-rose-500/30 font-medium"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Delete
                      </button>
                    ) : (
                      <span className="text-slate-500 font-mono">Protected</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Access Decisions */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-white">
          Recorded Access Decisions
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-2.5">Time</th>
                <th className="px-4 py-2.5">Actor / Device</th>
                <th className="px-4 py-2.5">Path</th>
                <th className="px-4 py-2.5">Resource:Action</th>
                <th className="px-4 py-2.5">Decision</th>
                <th className="px-4 py-2.5">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {decisions.map((d) => (
                <tr key={d.decision_id}>
                  <td className="px-4 py-2.5 font-mono text-slate-400">
                    {new Date(d.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-white">{d.username}</span>{" "}
                    <span className="text-slate-500 font-mono">({d.device_id ?? "none"})</span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-cyan-300">
                    {d.source_service} → {d.destination_service}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-slate-200">
                    {d.resource}:{d.action}
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusBadge value={d.decision} />
                  </td>
                  <td className="px-4 py-2.5 text-slate-300">{d.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
