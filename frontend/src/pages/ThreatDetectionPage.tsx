import React, { useEffect, useState } from "react";
import { Activity, GitBranch, Play, ShieldAlert } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { DatasetEvalMetrics, ThreatAlert } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
}

export const ThreatDetectionPage: React.FC<Props> = ({ token, deviceId }) => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [graph, setGraph] = useState<{
    allowed_topology: Record<string, string[]>;
    observed_edges: any[];
  } | null>(null);
  const [evalMetrics, setEvalMetrics] = useState<DatasetEvalMetrics | null>(null);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  // Simulation state
  const [simUser, setSimUser] = useState("bob.eng");
  const [simRole, setSimRole] = useState("Employee");
  const [simSrc, setSimSrc] = useState("node-c");
  const [simDst, setSimDst] = useState("node-a");
  const [simResource, setSimResource] = useState("keys");
  const [simAction, setSimAction] = useState("rotate");
  const [simDevStatus, setSimDevStatus] = useState("ACTIVE");
  const [simClockOffset, setSimClockOffset] = useState("0");
  const [timingPolicy, setTimingPolicy] = useState<any>(null);

  const loadData = async () => {
    try {
      const [al, gr] = await Promise.all([
        apiRequest<ThreatAlert[]>("/api/threats/alerts", { token, deviceId }),
        apiRequest<any>("/api/threats/graph", { token, deviceId }),
      ]);
      setAlerts(al);
      setGraph(gr);
      setTimingPolicy(gr.timing_policy ?? null);
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadData();
  }, [token, deviceId]);

  const handleEvaluateDataset = async () => {
    setFeedback(null);
    try {
      const metrics = await apiRequest<DatasetEvalMetrics>("/api/threats/evaluate-dataset", {
        method: "POST",
        token,
        deviceId,
      });
      setEvalMetrics(metrics);
      setFeedback({
        type: "ok",
        msg: `Evaluated ${metrics.total_events} labelled synthetic events: F1=${metrics.f1_score}, Precision=${metrics.precision}, Recall=${metrics.recall}.`,
      });
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const res = await apiRequest<{ alerts_triggered: ThreatAlert[] }>("/api/threats/simulate", {
        method: "POST",
        token,
        deviceId,
        body: {
          user_identity: simUser,
          role: simRole,
          device_status: simDevStatus,
          source_service: simSrc,
          destination_service: simDst,
          resource: simResource,
          action: simAction,
          decision: "DENY",
          clock_offset_seconds: Number(simClockOffset) || 0,
        },
      });
      setFeedback({
        type: res.alerts_triggered.length > 0 ? "err" : "ok",
        msg:
          res.alerts_triggered.length > 0
            ? `Triggered ${res.alerts_triggered.length} deterministic alert(s): ${res.alerts_triggered
                .map((a) => a.rule_triggered)
                .join(", ")}`
            : "Event evaluated as benign (0 alerts).",
      });
      await loadData();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Deterministic Threat Detection Engine</h1>
          <p className="text-sm text-slate-400">
            Zero AI/ML — strictly deterministic rule evaluation and directed service-graph topology analysis.
          </p>
        </div>
        <button
          onClick={handleEvaluateDataset}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
        >
          <Play className="w-4 h-4" />
          Evaluate Labelled Synthetic Dataset
        </button>
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

      {/* Synthetic Dataset Evaluation Metrics */}
      {evalMetrics && (
        <div className="p-5 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-cyan-300">
              Computed Evaluation Metrics ({evalMetrics.total_events} Labelled Events: {evalMetrics.benign_events} Benign / {evalMetrics.malicious_events} Malicious)
            </h2>
            <span className="text-xs font-mono text-slate-400">
              TP={evalMetrics.true_positives} FP={evalMetrics.false_positives} TN={evalMetrics.true_negatives} FN={evalMetrics.false_negatives}
            </span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">Precision</div>
              <div className="text-xl font-bold font-mono text-emerald-300">{evalMetrics.precision}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">Recall</div>
              <div className="text-xl font-bold font-mono text-cyan-300">{evalMetrics.recall}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">F1 Score</div>
              <div className="text-xl font-bold font-mono text-indigo-300">{evalMetrics.f1_score}</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">Median Alert Time</div>
              <div className="text-xl font-bold font-mono text-white">{evalMetrics.median_alert_time_ms} ms</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">False Alerts / 1k Benign</div>
              <div className="text-xl font-bold font-mono text-amber-300">{evalMetrics.false_alerts_per_1000_benign}</div>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(evalMetrics.category_breakdown).map(([cat, stats]) => (
              <span
                key={cat}
                className="text-xs font-mono px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-slate-300"
              >
                {cat}: {stats.detected}/{stats.total}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Clock-Skew & Ordering Policy */}
      {timingPolicy && (
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 flex flex-wrap items-center justify-between gap-2">
          <div>
            <span className="font-semibold text-cyan-300">Clock-Skew & Out-of-Order Policy: </span>
            {timingPolicy.policy_summary}
          </div>
          <span className="font-mono text-slate-400">
            Range: ±{timingPolicy.supported_clock_skew_seconds}s
          </span>
        </div>
      )}

      {/* Simulator + Service Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <form
          onSubmit={handleSimulate}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Activity className="w-4 h-4 text-amber-400" />
            Inject Security Event into Live Engine (Admin)
          </div>
          <div className="grid grid-cols-3 gap-2">
            <input
              type="text"
              value={simUser}
              onChange={(e) => setSimUser(e.target.value)}
              placeholder="User"
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            />
            <select
              value={simRole}
              onChange={(e) => setSimRole(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="Employee">Employee</option>
              <option value="Viewer">Viewer</option>
              <option value="Admin">Admin</option>
            </select>
            <select
              value={simDevStatus}
              onChange={(e) => setSimDevStatus(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="ACTIVE">Device ACTIVE</option>
              <option value="REVOKED">Device REVOKED</option>
            </select>
          </div>
          <div className="grid grid-cols-4 gap-2">
            <select
              value={simSrc}
              onChange={(e) => setSimSrc(e.target.value)}
              className="px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="client">src: client</option>
              <option value="node-a">src: node-a</option>
              <option value="node-b">src: node-b</option>
              <option value="node-c">src: node-c</option>
            </select>
            <select
              value={simDst}
              onChange={(e) => setSimDst(e.target.value)}
              className="px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            >
              <option value="node-a">dst: node-a</option>
              <option value="node-b">dst: node-b</option>
              <option value="node-c">dst: node-c</option>
              <option value="key-vault">dst: key-vault</option>
            </select>
            <input
              type="text"
              value={simResource}
              onChange={(e) => setSimResource(e.target.value)}
              placeholder="Resource"
              className="px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            />
            <input
              type="text"
              value={simAction}
              onChange={(e) => setSimAction(e.target.value)}
              placeholder="Action"
              className="px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400">Clock Offset (sec):</label>
            <input
              type="number"
              value={simClockOffset}
              onChange={(e) => setSimClockOffset(e.target.value)}
              className="w-28 px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white font-mono"
            />
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium"
            >
              Evaluate Event
            </button>
          </div>
        </form>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <GitBranch className="w-4 h-4 text-cyan-400" />
            Zero-Trust Directed Service Graph
          </div>
          {graph && (
            <div className="space-y-2 text-xs">
              <div className="text-slate-400">Allowed Topology Edges:</div>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(graph.allowed_topology).map(([src, dsts]) =>
                  dsts.length > 0 ? (
                    <span
                      key={src}
                      className="px-2 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-cyan-300"
                    >
                      {src} → [{dsts.join(", ")}]
                    </span>
                  ) : null
                )}
              </div>
              <div className="text-slate-400 pt-1">Observed Traffic Edges:</div>
              <div className="flex flex-wrap gap-1.5">
                {graph.observed_edges.map((e, idx) => (
                  <span
                    key={idx}
                    className={`px-2 py-1 rounded font-mono border ${
                      e.policy_allowed
                        ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                        : "bg-rose-500/10 border-rose-500/30 text-rose-300"
                    }`}
                  >
                    {e.source} → {e.destination} ({e.decision}: {e.count})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Live Alerts Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-white">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          Detected Threat Alerts
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">Time / Ordering</th>
                <th className="px-4 py-3">User Identity</th>
                <th className="px-4 py-3">Source → Destination</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Rule Triggered</th>
                <th className="px-4 py-3">Reason & Related Events</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-400">
                    No alerts recorded yet.
                  </td>
                </tr>
              ) : (
                alerts.map((a) => (
                  <tr key={a.alert_id}>
                    <td className="px-4 py-3 font-mono text-slate-400 space-y-1">
                      <div>{new Date(a.event_time).toLocaleTimeString()}</div>
                      {a.ordering_status && <StatusBadge value={a.ordering_status} />}
                    </td>
                    <td className="px-4 py-3 text-white font-medium">{a.user_identity}</td>
                    <td className="px-4 py-3 font-mono text-cyan-300">
                      {a.source_service} → {a.destination_service}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge value={a.severity} />
                    </td>
                    <td className="px-4 py-3 font-mono text-amber-300">{a.rule_triggered}</td>
                    <td className="px-4 py-3 text-slate-300">
                      <div>{a.reason}</div>
                      {a.related_events && a.related_events.length > 0 && (
                        <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                          events: {a.related_events.join(", ")}
                        </div>
                      )}
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
