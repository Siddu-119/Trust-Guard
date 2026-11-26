import React, { useEffect, useState } from "react";
import { RefreshCw, Server, Settings, Shield } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { ServiceNode } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
  onRefreshNodes: () => void;
}

export const SettingsPage: React.FC<Props> = ({ token, deviceId, onRefreshNodes }) => {
  const [nodes, setNodes] = useState<ServiceNode[]>([]);
  const [graceVersions, setGraceVersions] = useState(1);
  const [strictDevice, setStrictDevice] = useState(true);
  const [requireFs, setRequireFs] = useState(true);
  const [assumptions, setAssumptions] = useState<string[]>([]);
  const [pqcInfo, setPqcInfo] = useState<any>(null);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  const loadAll = async () => {
    try {
      const [n, s] = await Promise.all([
        apiRequest<ServiceNode[]>("/api/nodes", { token, deviceId }),
        apiRequest<any>("/api/settings", { token, deviceId }),
      ]);
      setNodes(n);
      setGraceVersions(Number(s.settings.key_grace_versions ?? 1));
      setStrictDevice(s.settings.zero_trust_strict_device_check === "true");
      setRequireFs(s.settings.require_ephemeral_forward_secrecy === "true");
      setAssumptions(s.security_assumptions ?? []);
      setPqcInfo(s.pqc_algorithms);
      onRefreshNodes();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadAll();
  }, [token, deviceId]);

  const handleToggleNode = async (nodeId: string, targetStatus: "ONLINE" | "OFFLINE") => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>(`/api/nodes/${nodeId}/status`, {
        method: "POST",
        token,
        deviceId,
        body: { status: targetStatus },
      });
      if (targetStatus === "ONLINE" && res.auto_sync) {
        setFeedback({
          type: "ok",
          msg: `${nodeId} restored ONLINE and auto-synced to key v${res.auto_sync.synced_key_version} (caught up ${res.auto_sync.caught_up_revocations} revocations in ${res.auto_sync.latency_ms} ms).`,
        });
      } else {
        setFeedback({ type: "ok", msg: `${nodeId} set to ${targetStatus}.` });
      }
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleManualSync = async (nodeId: string) => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>(`/api/nodes/${nodeId}/sync`, {
        method: "POST",
        token,
        deviceId,
      });
      setFeedback({
        type: "ok",
        msg: `Synced ${nodeId} to key v${res.synced_key_version} (${res.latency_ms} ms).`,
      });
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      await apiRequest("/api/settings", {
        method: "PUT",
        token,
        deviceId,
        body: {
          key_grace_versions: graceVersions,
          zero_trust_strict_device_check: strictDevice,
          require_ephemeral_forward_secrecy: requireFs,
        },
      });
      setFeedback({ type: "ok", msg: "Security policy settings saved." });
      await loadAll();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Service Nodes & Security Settings</h1>
        <p className="text-sm text-slate-400">
          Simulate node outages & recovery synchronization across Service Nodes A, B, C and configure key cutoff policy.
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

      {/* Service Nodes Management */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {nodes.map((node) => (
          <div
            key={node.node_id}
            className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <span className="font-semibold text-white text-sm">{node.name}</span>
              </div>
              <StatusBadge value={node.status} />
            </div>
            <div className="text-xs text-slate-400">{node.role}</div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-500">Synced Key Version:</span>
                <span className="text-cyan-300">v{node.synced_key_version}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Enforced Revocations:</span>
                <span className="text-slate-200">{node.revoked_devices_enforced}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Pending Sync:</span>
                <span className={node.pending_revocations > 0 ? "text-amber-300" : "text-slate-400"}>
                  {node.pending_revocations}
                </span>
              </div>
            </div>
            <div className="flex gap-2">
              {node.status === "ONLINE" ? (
                <button
                  onClick={() => handleToggleNode(node.node_id, "OFFLINE")}
                  className="flex-1 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 text-xs font-medium"
                >
                  Simulate Offline
                </button>
              ) : (
                <button
                  onClick={() => handleToggleNode(node.node_id, "ONLINE")}
                  className="flex-1 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium"
                >
                  Bring Online & Sync
                </button>
              )}
              <button
                onClick={() => handleManualSync(node.node_id)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs"
                title="Manual Sync"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Policy Settings & Security Architecture */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <form
          onSubmit={handleSaveSettings}
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Settings className="w-4 h-4 text-cyan-400" />
            Key Cutoff & Zero-Trust Policy (Admin)
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Previous Key Version Grace Window (Cutoff Policy)
            </label>
            <input
              type="number"
              min={0}
              max={10}
              value={graceVersions}
              onChange={(e) => setGraceVersions(Number(e.target.value))}
              className="w-32 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white font-mono"
            />
            <p className="text-xs text-slate-500 mt-1">
              Keys older than (ActiveVersion - {graceVersions}) are automatically marked EXPIRED_CUTOFF and rejected.
            </p>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={strictDevice}
              onChange={(e) => setStrictDevice(e.target.checked)}
            />
            Enforce Zero-Trust device revocation check on every API call
          </label>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={requireFs}
              onChange={(e) => setRequireFs(e.target.checked)}
            />
            Require ephemeral ML-KEM-768 forward secrecy for secure messages
          </label>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
          >
            Save Settings
          </button>
        </form>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Shield className="w-4 h-4 text-emerald-400" />
            Verified Post-Quantum Stack & Security Assumptions
          </div>
          {pqcInfo && (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
              <div>KEM: <span className="text-cyan-300">{pqcInfo.kem}</span></div>
              <div>Signature: <span className="text-cyan-300">{pqcInfo.signature}</span></div>
              <div>Symmetric: <span className="text-cyan-300">{pqcInfo.symmetric}</span></div>
              <div>Library Active: <span className="text-emerald-300">{String(pqcInfo.pqc_available)}</span></div>
            </div>
          )}
          <ul className="space-y-2 text-xs text-slate-300 list-disc pl-4">
            {assumptions.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
