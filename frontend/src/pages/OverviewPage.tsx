import React, { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertTriangle,
  KeyRound,
  Laptop,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldOff,
  Users,
} from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { DashboardOverview } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
  onRefreshNodes: () => void;
}

const PIE_COLORS = ["#f43f5e", "#f97316", "#eab308", "#38bdf8"];

export const OverviewPage: React.FC<Props> = ({ token, deviceId, onRefreshNodes }) => {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadOverview = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<DashboardOverview>("/api/dashboard/overview", {
        token,
        deviceId,
      });
      setData(res);
      onRefreshNodes();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
  }, [token, deviceId]);

  if (loading && !data) {
    return <div className="text-slate-400 text-sm">Loading live platform telemetry...</div>;
  }

  if (error && !data) {
    return (
      <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
        {error}
      </div>
    );
  }

  if (!data) return null;

  const kpis = [
    { label: "Total Registered Users", value: data.metrics.total_users, icon: Users, accent: "text-cyan-400" },
    { label: "Active Devices", value: data.metrics.active_devices, icon: Laptop, accent: "text-emerald-400" },
    { label: "Active Cryptographic Keys", value: data.metrics.active_keys, icon: KeyRound, accent: "text-indigo-400" },
    { label: "Revoked Devices", value: data.metrics.revoked_devices, icon: ShieldOff, accent: "text-rose-400" },
    { label: "Suspicious Activities", value: data.metrics.suspicious_activities, icon: ShieldAlert, accent: "text-amber-400" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Security Operations Overview</h1>
          <p className="text-sm text-slate-400">
            Real-time telemetry from SQLite state, post-quantum key lifecycle, and service nodes.
          </p>
        </div>
        <button
          onClick={loadOverview}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm font-medium border border-slate-700"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh Telemetry
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
        {kpis.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div
              key={kpi.label}
              className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start justify-between"
            >
              <div>
                <div className="text-xs font-medium text-slate-400">{kpi.label}</div>
                <div className="text-2xl font-bold text-white mt-1.5 font-mono">{kpi.value}</div>
              </div>
              <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                <Icon className={`w-5 h-5 ${kpi.accent}`} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Key Rotation Status + Service Nodes */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Key Rotation State Machine</h2>
            <StatusBadge value={data.key_rotation_status.state} />
          </div>
          <div className="text-xs text-slate-400">
            Recoverable two-phase rotation (<span className="font-mono text-slate-200">PENDING → COMMITTED</span>).
          </div>
          {data.key_rotation_status.latest_rotation ? (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Rotation ID:</span>
                <span className="text-slate-200">{data.key_rotation_status.latest_rotation.rotation_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Version:</span>
                <span className="text-cyan-300">
                  v{data.key_rotation_status.latest_rotation.old_version ?? 0} → v{data.key_rotation_status.latest_rotation.new_version}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Recovered:</span>
                <span className="text-slate-200">
                  {data.key_rotation_status.latest_rotation.recovered ? "YES" : "NO"}
                </span>
              </div>
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
              No rotations executed yet; baseline v1 keys active.
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            {data.key_rotation_status.key_breakdown.map((b) => (
              <span
                key={b.status}
                className="text-xs px-2 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-slate-300"
              >
                {b.status}: {b.count}
              </span>
            ))}
          </div>
        </div>

        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Simulated Service Nodes Synchronization</h2>
            <span className="text-xs text-slate-400 font-mono">Persistent State</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {data.service_nodes.map((node) => (
              <div
                key={node.node_id}
                className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <span className="text-sm font-medium text-white">{node.name}</span>
                  </div>
                  <StatusBadge value={node.status} />
                </div>
                <div className="text-xs text-slate-400">{node.role}</div>
                <div className="pt-1 border-t border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Key Ver:</span>
                    <span className="text-cyan-300">v{node.synced_key_version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Enforced Revs:</span>
                    <span className="text-slate-200">{node.revoked_devices_enforced}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Sync Latency:</span>
                    <span className="text-emerald-300">{node.last_sync_latency_ms} ms</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
          <h2 className="text-sm font-semibold text-white mb-1">Access Activity by Service Node</h2>
          <p className="text-xs text-slate-400 mb-4">Server-side Zero-Trust ALLOW vs DENY decisions</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.charts.access_activity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="service" stroke="#94a3b8" fontSize={12} />
                <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                  }}
                />
                <Bar dataKey="allow_count" name="Allowed" fill="#10b981" radius={[4, 4, 0, 0]} />
                <Bar dataKey="deny_count" name="Denied" fill="#f43f5e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
          <h2 className="text-sm font-semibold text-white mb-1">Security Events by Severity</h2>
          <p className="text-xs text-slate-400 mb-4">Deterministic rule & graph threat alerts</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.charts.security_events}
                  dataKey="count"
                  nameKey="category"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                >
                  {data.charts.security_events.map((entry, idx) => (
                    <Cell key={entry.category} fill={PIE_COLORS[idx % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap justify-center gap-4 text-xs mt-1">
            {data.charts.security_events.map((s, idx) => (
              <div key={s.category} className="flex items-center gap-1.5">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: PIE_COLORS[idx % PIE_COLORS.length] }}
                />
                <span className="text-slate-300 font-mono">
                  {s.category}: {s.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Security Events & Audit Trail */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-semibold text-white">Recent Security Events (Threat Alerts)</h2>
          </div>
          {data.recent_security_events.length === 0 ? (
            <div className="text-xs text-slate-400 py-6 text-center border border-dashed border-slate-800 rounded-lg">
              No suspicious alerts triggered yet. Simulate threats or run denied actions to observe detections.
            </div>
          ) : (
            <div className="space-y-2">
              {data.recent_security_events.map((ev) => (
                <div
                  key={ev.alert_id}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-cyan-300">{ev.rule_triggered}</span>
                    <StatusBadge value={ev.severity} />
                  </div>
                  <div className="text-slate-300">{ev.reason}</div>
                  <div className="text-slate-500 font-mono">
                    {ev.user_identity} • {ev.source_service} → {ev.destination_service}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
          <h2 className="text-sm font-semibold text-white mb-3">Recent Tamper-Evident Audit Entries</h2>
          <div className="space-y-2">
            {data.recent_audit_events.map((evt) => (
              <div
                key={evt.event_id}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="font-mono text-slate-200 truncate">
                    #{evt.seq} {evt.action} → {evt.resource}
                  </div>
                  <div className="text-slate-500 font-mono truncate">
                    actor={evt.actor_id} • hash={evt.current_hash.slice(0, 16)}...
                  </div>
                </div>
                <StatusBadge value={evt.result} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
