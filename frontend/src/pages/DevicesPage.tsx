import React, { useEffect, useState } from "react";
import { Laptop, Plus, RefreshCcw, ShieldOff } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { DeviceRecord, UserRecord } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
  onRefreshNodes: () => void;
}

export const DevicesPage: React.FC<Props> = ({ token, deviceId, onRefreshNodes }) => {
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  // Register device form
  const [ownerId, setOwnerId] = useState("usr-bob");
  const [deviceName, setDeviceName] = useState("");
  const [deviceType, setDeviceType] = useState("Workstation");

  // Replace revoked device form
  const [revokedDeviceId, setRevokedDeviceId] = useState("");
  const [replacementName, setReplacementName] = useState("");

  const loadDevices = async () => {
    try {
      const [devs, usrs] = await Promise.all([
        apiRequest<DeviceRecord[]>("/api/devices", { token, deviceId }),
        apiRequest<UserRecord[]>("/api/users", { token, deviceId }),
      ]);
      setDevices(devs);
      setUsers(usrs);
      const firstRevoked = devs.find((d) => d.status === "REVOKED");
      if (firstRevoked && !revokedDeviceId) {
        setRevokedDeviceId(firstRevoked.device_id);
      }
      onRefreshNodes();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadDevices();
  }, [token, deviceId]);

  const handleRevoke = async (targetDeviceId: string) => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>(`/api/devices/${targetDeviceId}/revoke`, {
        method: "POST",
        token,
        deviceId,
        body: { reason: "Reported lost / stolen via Device Management" },
      });
      const summary = res.node_propagation
        .map((n: any) =>
          n.status === "ENFORCED"
            ? `${n.node_id}: ENFORCED (${n.enforcement_ms} ms)`
            : `${n.node_id}: PENDING_SYNC (OFFLINE)`
        )
        .join(" | ");
      setFeedback({
        type: "ok",
        msg: `Device ${targetDeviceId} revoked. Propagation → ${summary}`,
      });
      setRevokedDeviceId(targetDeviceId);
      await loadDevices();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const created = await apiRequest<DeviceRecord>("/api/devices", {
        method: "POST",
        token,
        deviceId,
        body: { owner_id: ownerId, device_name: deviceName, device_type: deviceType },
      });
      setFeedback({
        type: "ok",
        msg: `Registered device ${created.device_id} for ${created.owner_username}.`,
      });
      setDeviceName("");
      await loadDevices();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleReplace = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const created = await apiRequest<DeviceRecord>("/api/devices/replace", {
        method: "POST",
        token,
        deviceId,
        body: {
          revoked_device_id: revokedDeviceId,
          new_device_name: replacementName,
          device_type: "Workstation",
        },
      });
      setFeedback({
        type: "ok",
        msg: `Enrolled replacement device ${created.device_id} (replaces ${revokedDeviceId}). Other users' access preserved.`,
      });
      setReplacementName("");
      await loadDevices();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const revokedOptions = devices.filter((d) => d.status === "REVOKED");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Device Management & Revocation Propagation</h1>
        <p className="text-sm text-slate-400">
          Revoke lost/compromised endpoints, inspect per-node enforcement timing across Nodes A/B/C, and enroll replacements.
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <form
          onSubmit={handleRegister}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Plus className="w-4 h-4 text-cyan-400" />
            Enroll New Device
          </div>
          <div className="grid grid-cols-2 gap-2">
            <select
              value={ownerId}
              onChange={(e) => setOwnerId(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              {users.map((u) => (
                <option key={u.user_id} value={u.user_id}>
                  {u.username} ({u.role})
                </option>
              ))}
            </select>
            <select
              value={deviceType}
              onChange={(e) => setDeviceType(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="Workstation">Workstation</option>
              <option value="Tablet">Tablet</option>
              <option value="Hardware Token">Hardware Token</option>
            </select>
          </div>
          <input
            type="text"
            required
            value={deviceName}
            onChange={(e) => setDeviceName(e.target.value)}
            placeholder="Device Name (e.g. Bob Linux Workstation)"
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
          />
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
          >
            Register Device
          </button>
        </form>

        <form
          onSubmit={handleReplace}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <RefreshCcw className="w-4 h-4 text-emerald-400" />
            Enroll Replacement for Revoked Device
          </div>
          <select
            value={revokedDeviceId}
            onChange={(e) => setRevokedDeviceId(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
          >
            <option value="">Select revoked device...</option>
            {revokedOptions.map((d) => (
              <option key={d.device_id} value={d.device_id}>
                {d.device_id} — {d.owner_username} ({d.device_name})
              </option>
            ))}
          </select>
          <input
            type="text"
            required
            disabled={!revokedDeviceId}
            value={replacementName}
            onChange={(e) => setReplacementName(e.target.value)}
            placeholder="Replacement Device Name"
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white disabled:opacity-40"
          />
          <button
            type="submit"
            disabled={!revokedDeviceId}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-sm font-medium"
          >
            Enroll Replacement Device
          </button>
        </form>
      </div>

      {/* Devices Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-white">
          <Laptop className="w-4 h-4 text-cyan-400" />
          Registered Endpoints & Multi-Node Enforcement
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">Device ID / Name</th>
                <th className="px-4 py-3">Owner</th>
                <th className="px-4 py-3">Registered / Last Activity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Node Enforcement Latency</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {devices.map((d) => (
                <tr key={d.device_id} className="hover:bg-slate-800/40">
                  <td className="px-4 py-3">
                    <div className="font-mono text-cyan-300">{d.device_id}</div>
                    <div className="text-white">{d.device_name}</div>
                    {d.replaces_device_id && (
                      <div className="text-[11px] font-mono text-emerald-400">
                        Replaces: {d.replaces_device_id}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-white">{d.owner_username}</div>
                    <div className="text-slate-500">{d.device_type}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-400">
                    <div>Reg: {new Date(d.registered_at).toLocaleDateString()}</div>
                    <div>Act: {new Date(d.last_activity).toLocaleTimeString()}</div>
                    {d.revoked_at && (
                      <div className="text-rose-400">
                        Rev: {new Date(d.revoked_at).toLocaleTimeString()}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge value={d.status} />
                  </td>
                  <td className="px-4 py-3">
                    {d.node_enforcement.length === 0 ? (
                      <span className="text-slate-500">All nodes active</span>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {d.node_enforcement.map((ne) => (
                          <span
                            key={ne.node_id}
                            className={`px-2 py-0.5 rounded font-mono border ${
                              ne.status === "ENFORCED"
                                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                                : "bg-amber-500/10 border-amber-500/30 text-amber-300"
                            }`}
                          >
                            {ne.node_id}:{" "}
                            {ne.status === "ENFORCED"
                              ? `${ne.enforcement_ms} ms`
                              : "PENDING_SYNC"}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {d.status === "ACTIVE" ? (
                      <button
                        onClick={() => handleRevoke(d.device_id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/35 text-rose-300 border border-rose-500/30 font-medium"
                      >
                        <ShieldOff className="w-3.5 h-3.5" />
                        Report Lost / Revoke
                      </button>
                    ) : (
                      <span className="text-slate-500 font-mono">Blocked</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
