import React, { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, DatabaseBackup, RotateCcw, ShieldCheck } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { BackupRecord } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
}

export const RecoveryBackupsPage: React.FC<Props> = ({ token, deviceId }) => {
  const [backups, setBackups] = useState<BackupRecord[]>([]);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  const loadBackups = async () => {
    try {
      const data = await apiRequest<BackupRecord[]>("/api/backups", { token, deviceId });
      setBackups(data);
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadBackups();
  }, [token, deviceId]);

  const handleCreateBackup = async () => {
    setFeedback(null);
    try {
      const bkp = await apiRequest<BackupRecord>("/api/backups", {
        method: "POST",
        token,
        deviceId,
      });
      setFeedback({
        type: "ok",
        msg: `Created AES-256-GCM encrypted & ML-DSA-65 signed backup ${bkp.backup_id} (${bkp.key_count} keys, ${bkp.revoked_count} revoked).`,
      });
      await loadBackups();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleVerify = async (backupId: string) => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>(`/api/backups/${backupId}/verify`, {
        method: "POST",
        token,
        deviceId,
      });
      setFeedback({
        type: res.valid ? "ok" : "err",
        msg: `${res.status}: ${res.reason}`,
      });
      await loadBackups();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleRestore = async (backupId: string) => {
    setFeedback(null);
    try {
      const res = await apiRequest<any>(`/api/backups/${backupId}/restore`, {
        method: "POST",
        token,
        deviceId,
      });
      setFeedback({
        type: "ok",
        msg: `Safely restored ${backupId}: ${res.restored_keys} restored, ${res.committed_preserved} committed preserved, ${res.revoked_preserved} revoked keys preserved.`,
      });
      await loadBackups();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleSimulateCorruption = async (backupId: string) => {
    setFeedback(null);
    try {
      await apiRequest(`/api/backups/${backupId}/simulate-corruption`, {
        method: "POST",
        token,
        deviceId,
      });
      setFeedback({
        type: "err",
        msg: `Injected 1-byte ciphertext corruption into ${backupId}. Run 'Verify Integrity' or 'Restore' to observe rejection.`,
      });
      await loadBackups();
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
        msg: `Rotation crash recovery complete: ${res.recovered_count} PENDING rotation(s) processed.`,
      });
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Recovery & Encrypted Key Backups</h1>
          <p className="text-sm text-slate-400">
            AES-256-GCM encrypted & ML-DSA-65 signed backups, corruption detection, and safe recovery preserving committed & revoked keys.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleRecoverRotations}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 text-sm font-medium"
          >
            <RotateCcw className="w-4 h-4" />
            Recover Interrupted Rotations
          </button>
          <button
            onClick={handleCreateBackup}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
          >
            <DatabaseBackup className="w-4 h-4" />
            Create Encrypted Backup
          </button>
        </div>
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

      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-white">
          Encrypted Key Backup Vault
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">Backup ID</th>
                <th className="px-4 py-3">Created By / Time</th>
                <th className="px-4 py-3">Keys (Revoked)</th>
                <th className="px-4 py-3">Payload SHA-256</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {backups.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-400">
                    No backups created yet. Click "Create Encrypted Backup" (Admin) to generate an authenticated snapshot.
                  </td>
                </tr>
              ) : (
                backups.map((b) => (
                  <tr key={b.backup_id}>
                    <td className="px-4 py-3 font-mono text-cyan-300">{b.backup_id}</td>
                    <td className="px-4 py-3">
                      <div className="text-white font-mono">{b.created_by}</div>
                      <div className="text-slate-500 font-mono">
                        {new Date(b.created_at).toLocaleString()}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-white">
                      {b.key_count} total ({b.revoked_count} revoked)
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400">
                      {b.payload_sha256.slice(0, 20)}...
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge value={b.status} />
                    </td>
                    <td className="px-4 py-3 space-x-2">
                      <button
                        onClick={() => handleVerify(b.backup_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                      >
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        Verify Integrity
                      </button>
                      <button
                        onClick={() => handleRestore(b.backup_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-indigo-600/20 hover:bg-indigo-600/35 text-indigo-300 border border-indigo-500/30"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Safe Restore
                      </button>
                      <button
                        onClick={() => handleSimulateCorruption(b.backup_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-rose-600/20 hover:bg-rose-600/35 text-rose-300 border border-rose-500/30"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Inject Corruption (Demo)
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
