import React from "react";

const VARIANT_MAP: Record<string, string> = {
  ACTIVE: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  ALLOW: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  ONLINE: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  DELIVERED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  COMMITTED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  VALID: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  ENFORCED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  SUCCESS: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  IN_ORDER: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",

  PENDING: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  PENDING_SYNC: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  OUT_OF_ORDER_UNCERTAIN: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  CLOCK_OFFSET_ADJUSTED: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  CLOCK_SKEW_EXCEEDED: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  RETIRED: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  LOW: "bg-sky-500/15 text-sky-300 border-sky-500/30",

  REVOKED: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  DENY: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  REJECTED_REPLAY: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  REJECTED_TAMPERED: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  REJECTED_INVALID: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  REJECTED_HIJACK: "bg-rose-500/20 text-rose-200 border-rose-500/40",
  REJECTED_REVOKED: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  OFFLINE: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  EXPIRED_CUTOFF: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  CORRUPTED: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  CRITICAL: "bg-rose-500/20 text-rose-200 border-rose-500/40",
  ROLLED_BACK: "bg-rose-500/15 text-rose-300 border-rose-500/30",

  Admin: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  Employee: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
  Viewer: "bg-slate-500/20 text-slate-300 border-slate-500/30",
};

export const StatusBadge: React.FC<{ value: string; className?: string }> = ({
  value,
  className = "",
}) => {
  const style =
    VARIANT_MAP[value] ?? "bg-slate-800 text-slate-300 border-slate-700";
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${style} ${className}`}
    >
      {value}
    </span>
  );
};
