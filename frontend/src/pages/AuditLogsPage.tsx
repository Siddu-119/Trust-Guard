import React, { useEffect, useState } from "react";
import { CheckCircle2, FileCheck2, ShieldAlert } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { AuditEvent, AuditVerification } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
}

export const AuditLogsPage: React.FC<Props> = ({ token, deviceId }) => {
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadLogs = async () => {
    try {
      const data = await apiRequest<AuditEvent[]>("/api/audit/logs?limit=100", {
        token,
        deviceId,
      });
      setLogs(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [token, deviceId]);

  const handleVerifyChain = async () => {
    setError(null);
    try {
      const res = await apiRequest<AuditVerification>("/api/audit/verify", {
        token,
        deviceId,
      });
      setVerification(res);
      await loadLogs();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Tamper-Evident Audit Logs</h1>
          <p className="text-sm text-slate-400">
            Canonical JSON SHA-256 hash chain from GENESIS. Passwords, private keys, and plaintext messages are never logged.
          </p>
        </div>
        <button
          onClick={handleVerifyChain}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
        >
          <FileCheck2 className="w-4 h-4" />
          Verify Audit Log Chain
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
          {error}
        </div>
      )}

      {verification && (
        <div
          className={`p-4 rounded-xl border flex items-start gap-3 ${
            verification.valid
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
              : "bg-rose-500/10 border-rose-500/40 text-rose-200"
          }`}
        >
          {verification.valid ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          )}
          <div className="text-sm space-y-1">
            <div className="font-semibold">
              {verification.tampered
                ? "TAMPERING DETECTED IN AUDIT CHAIN!"
                : "Audit Hash Chain Verified Clean"}
            </div>
            <div className="text-xs opacity-90">{verification.reason}</div>
            <div className="text-xs font-mono opacity-80">
              Checked Events: {verification.checked_events}
              {verification.latest_hash ? ` | Head Hash: ${verification.latest_hash}` : ""}
              {verification.broken_event_id ? ` | Broken Event: ${verification.broken_event_id}` : ""}
            </div>
          </div>
        </div>
      )}

      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">Seq / Event ID</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Action / Resource</th>
                <th className="px-4 py-3">Result</th>
                <th className="px-4 py-3">Previous Hash → Current Hash</th>
                <th className="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {logs.map((l) => (
                <tr key={l.event_id} className="hover:bg-slate-800/40">
                  <td className="px-4 py-3 font-mono">
                    <div className="text-white">#{l.seq}</div>
                    <div className="text-cyan-300">{l.event_id}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-200">{l.actor_id}</td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-white">{l.action}</div>
                    <div className="text-slate-400 font-mono">{l.resource}</div>
                    {l.metadata_json !== "{}" && (
                      <div className="text-[11px] font-mono text-slate-500 max-w-xs truncate">
                        {l.metadata_json}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge value={l.result} />
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px]">
                    <div className="text-slate-500">
                      prev: {l.previous_hash === "GENESIS" ? "GENESIS" : l.previous_hash.slice(0, 16) + "..."}
                    </div>
                    <div className="text-emerald-300">curr: {l.current_hash.slice(0, 16)}...</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-400">
                    {new Date(l.timestamp).toLocaleString()}
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
