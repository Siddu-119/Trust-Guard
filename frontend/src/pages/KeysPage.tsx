import React, { useEffect, useState } from "react";
import { AlertOctagon, CheckCircle2, KeyRound, Plus, RotateCw } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { CryptoKey, KeyRotation } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
}

export const KeysPage: React.FC<Props> = ({ token, deviceId }) => {
  const [keys, setKeys] = useState<CryptoKey[]>([]);
  const [rotations, setRotations] = useState<KeyRotation[]>([]);
  const [graceVersions, setGraceVersions] = useState<number>(1);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  // Generate form
  const [genPurpose, setGenPurpose] = useState("NODE_TRANSPORT");
  const [genOwner, setGenOwner] = useState("system");
  const [genAlgo, setGenAlgo] = useState("ML-KEM-768");

  // Rotate form
  const [rotPurpose, setRotPurpose] = useState("NODE_TRANSPORT");
  const [rotOwner, setRotOwner] = useState("system");
  const [simulateCrash, setSimulateCrash] = useState(false);

  const loadKeys = async () => {
    try {
      const res = await apiRequest<{
        keys: CryptoKey[];
        rotations: KeyRotation[];
        grace_versions: number;
      }>("/api/keys", { token, deviceId });
      setKeys(res.keys);
      setRotations(res.rotations);
      setGraceVersions(res.grace_versions);
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadKeys();
  }, [token, deviceId]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const created = await apiRequest<CryptoKey>("/api/keys/generate", {
        method: "POST",
        token,
        deviceId,
        body: { purpose: genPurpose, owner_id: genOwner, algorithm: genAlgo },
      });
      setFeedback({
        type: "ok",
        msg: `Generated ${created.algorithm} key ${created.key_id} (v${created.version}). Private key wrapped at rest.`,
      });
      await loadKeys();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleRotate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const res = await apiRequest<any>("/api/keys/rotate", {
        method: "POST",
        token,
        deviceId,
        body: { purpose: rotPurpose, owner_id: rotOwner, simulate_crash: simulateCrash },
      });
      if (res.interrupted) {
        setFeedback({
          type: "err",
          msg: `Crash simulated mid-rotation! Rotation ${res.rotation.rotation_id} is stuck in PENDING state. Use 'Recover Interrupted Rotations' to safely complete commit.`,
        });
      } else {
        setFeedback({
          type: "ok",
          msg: `Rotation ${res.rotation.rotation_id} committed to v${res.new_key.version}. Expired cutoff keys: ${res.expired_cutoff_keys.length}.`,
        });
      }
      await loadKeys();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleRecoverRotations = async () => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>("/api/keys/recover-rotation", {
        method: "POST",
        token,
        deviceId,
      });
      setFeedback({
        type: "ok",
        msg: `Recovered ${res.recovered_count} interrupted PENDING rotation(s) safely.`,
      });
      await loadKeys();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleVerifyKeyUsage = async (keyId: string) => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>("/api/keys/verify-usage", {
        method: "POST",
        token,
        deviceId,
        body: { key_id: keyId },
      });
      setFeedback({
        type: res.accepted ? "ok" : "err",
        msg: `${res.accepted ? "ACCEPTED" : "REJECTED"}: ${res.reason}`,
      });
      await loadKeys();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    setFeedback(null);
    try {
      await apiRequest(`/api/keys/${keyId}/revoke`, {
        method: "POST",
        token,
        deviceId,
        body: { reason: "Manual administrative key revocation" },
      });
      setFeedback({ type: "ok", msg: `Key ${keyId} permanently REVOKED.` });
      await loadKeys();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const pendingRotations = rotations.filter((r) => r.state === "PENDING");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Post-Quantum Key Management</h1>
          <p className="text-sm text-slate-400">
            ML-KEM-768 & ML-DSA-65 lifecycle, recoverable{" "}
            <span className="font-mono text-slate-200">PENDING → COMMITTED</span> rotation, and cutoff policy (grace={graceVersions} version). Private keys never leave the server.
          </p>
        </div>
        {pendingRotations.length > 0 && (
          <button
            onClick={handleRecoverRotations}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium"
          >
            <AlertOctagon className="w-4 h-4" />
            Recover {pendingRotations.length} Pending Rotation(s)
          </button>
        )}
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
        {/* Generate Keypair */}
        <form
          onSubmit={handleGenerate}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Plus className="w-4 h-4 text-cyan-400" />
            Generate Post-Quantum Keypair
          </div>
          <div className="grid grid-cols-3 gap-2">
            <select
              value={genPurpose}
              onChange={(e) => setGenPurpose(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="NODE_TRANSPORT">NODE_TRANSPORT</option>
              <option value="IDENTITY_SIGNING">IDENTITY_SIGNING</option>
              <option value="BACKUP_SIGNING">BACKUP_SIGNING</option>
            </select>
            <input
              type="text"
              value={genOwner}
              onChange={(e) => setGenOwner(e.target.value)}
              placeholder="Owner ID (system or usr-...)"
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            />
            <select
              value={genAlgo}
              onChange={(e) => setGenAlgo(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="ML-KEM-768">ML-KEM-768</option>
              <option value="ML-DSA-65">ML-DSA-65</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
          >
            Generate Keypair
          </button>
        </form>

        {/* Rotate Key */}
        <form
          onSubmit={handleRotate}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <RotateCw className="w-4 h-4 text-indigo-400" />
            Rotate Key (PENDING → COMMITTED State Machine)
          </div>
          <div className="grid grid-cols-2 gap-2">
            <select
              value={rotPurpose}
              onChange={(e) => setRotPurpose(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="NODE_TRANSPORT">NODE_TRANSPORT (system)</option>
              <option value="BACKUP_SIGNING">BACKUP_SIGNING (system)</option>
              <option value="IDENTITY_SIGNING">IDENTITY_SIGNING</option>
            </select>
            <input
              type="text"
              value={rotOwner}
              onChange={(e) => setRotOwner(e.target.value)}
              placeholder="Owner ID"
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            />
          </div>
          <label className="flex items-center gap-2 text-xs text-amber-300">
            <input
              type="checkbox"
              checked={simulateCrash}
              onChange={(e) => setSimulateCrash(e.target.checked)}
              className="rounded border-slate-700 bg-slate-950"
            />
            Simulate mid-rotation crash (leaves state in PENDING for recovery demo)
          </label>
          <div className="flex gap-2">
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium"
            >
              Execute Key Rotation
            </button>
            <button
              type="button"
              onClick={handleRecoverRotations}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-sm font-medium"
            >
              Recover Pending
            </button>
          </div>
        </form>
      </div>

      {/* Keys Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <KeyRound className="w-4 h-4 text-cyan-400" />
            Cryptographic Key Registry (Public Keys & Metadata Only)
          </div>
          <span className="text-xs font-mono text-slate-400">Grace Window: {graceVersions} version(s)</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">Key ID</th>
                <th className="px-4 py-3">Purpose / Owner</th>
                <th className="px-4 py-3">Algorithm</th>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Public Key Prefix</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {keys.map((k) => (
                <tr key={k.key_id} className="hover:bg-slate-800/40">
                  <td className="px-4 py-3 font-mono text-cyan-300">{k.key_id}</td>
                  <td className="px-4 py-3">
                    <div className="text-white">{k.purpose}</div>
                    <div className="text-slate-500 font-mono">{k.owner_id}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-200">{k.algorithm}</td>
                  <td className="px-4 py-3 font-mono text-white">v{k.version}</td>
                  <td className="px-4 py-3">
                    <StatusBadge value={k.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-400">
                    {k.public_key_b64.slice(0, 20)}...
                  </td>
                  <td className="px-4 py-3 space-x-2">
                    <button
                      onClick={() => handleVerifyKeyUsage(k.key_id)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                    >
                      Test Cutoff
                    </button>
                    {k.status !== "REVOKED" && (
                      <button
                        onClick={() => handleRevokeKey(k.key_id)}
                        className="px-2.5 py-1 rounded bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Rotation History */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-white">
          Key Rotation State Machine Log
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-2.5">Rotation ID</th>
                <th className="px-4 py-2.5">Target</th>
                <th className="px-4 py-2.5">Versions</th>
                <th className="px-4 py-2.5">State</th>
                <th className="px-4 py-2.5">Recovered</th>
                <th className="px-4 py-2.5">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {rotations.map((r) => (
                <tr key={r.rotation_id}>
                  <td className="px-4 py-2.5 font-mono text-cyan-300">{r.rotation_id}</td>
                  <td className="px-4 py-2.5 font-mono">
                    {r.purpose} ({r.owner_id})
                  </td>
                  <td className="px-4 py-2.5 font-mono">
                    v{r.old_version ?? 0} → v{r.new_version}
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusBadge value={r.state} />
                  </td>
                  <td className="px-4 py-2.5 font-mono">
                    {r.recovered ? (
                      <span className="inline-flex items-center gap-1 text-emerald-300">
                        <CheckCircle2 className="w-3.5 h-3.5" /> YES
                      </span>
                    ) : (
                      "NO"
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-slate-300">{r.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
