import React, { useState } from "react";
import {
  Activity,
  DatabaseBackup,
  FileCheck2,
  KeyRound,
  Laptop,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  MessageSquareLock,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { AuthUser, NavTab, ServiceNode } from "../types";
import { StatusBadge } from "./StatusBadge";

interface LayoutProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  user: AuthUser;
  nodes: ServiceNode[];
  onLogout: () => void;
  children: React.ReactNode;
}

const NAV_ITEMS: { id: NavTab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "users", label: "Users & Identities", icon: Users },
  { id: "keys", label: "Key Management", icon: KeyRound },
  { id: "messages", label: "Secure Messages", icon: MessageSquareLock },
  { id: "devices", label: "Device Management", icon: Laptop },
  { id: "threats", label: "Threat Detection", icon: ShieldAlert },
  { id: "audit", label: "Audit Logs", icon: FileCheck2 },
  { id: "backups", label: "Recovery & Backups", icon: DatabaseBackup },
  { id: "settings", label: "Settings", icon: Settings },
];

export const Layout: React.FC<LayoutProps> = ({
  activeTab,
  onSelectTab,
  user,
  nodes,
  onLogout,
  children,
}) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  const sidebarContent = (
    <div className="flex flex-col h-full bg-slate-900 border-r border-slate-800">
      <div className="px-5 py-5 border-b border-slate-800 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="text-base font-semibold tracking-tight text-white">TrustGuard</div>
          <div className="text-[11px] text-cyan-400 font-mono">PQ-ZERO-TRUST v1.0</div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => {
                onSelectTab(item.id);
                setMobileOpen(false);
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                active
                  ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 border border-transparent"
              }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800 space-y-3">
        <div className="rounded-lg bg-slate-950 border border-slate-800 p-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium text-slate-300">{user.username}</span>
            <StatusBadge value={user.role} />
          </div>
          <div className="text-[11px] text-slate-400 font-mono truncate">
            Device: {user.device_id ?? "No device bound"}
          </div>
        </div>
        <button
          onClick={onLogout}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
        >
          <LogOut className="w-3.5 h-3.5" />
          Switch Identity / Sign Out
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:block w-64 shrink-0">{sidebarContent}</aside>

      {/* Mobile Sidebar */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-64 h-full">{sidebarContent}</div>
          <div
            className="flex-1 bg-black/60"
            onClick={() => setMobileOpen(false)}
          />
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 bg-slate-900/80 border-b border-slate-800 px-4 lg:px-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="lg:hidden p-2 rounded-lg bg-slate-800 text-slate-300"
              aria-label="Toggle Menu"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <div className="flex items-center gap-2 text-xs font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/25 px-2.5 py-1 rounded-md">
              <Lock className="w-3.5 h-3.5" />
              <span>ML-KEM-768 + ML-DSA-65 + AES-256-GCM</span>
            </div>
          </div>

          <div className="hidden md:flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-400 mr-1" />
            {nodes.map((node) => (
              <div
                key={node.node_id}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 text-xs"
              >
                <span
                  className={`w-2 h-2 rounded-full ${
                    node.status === "ONLINE" ? "bg-emerald-400" : "bg-rose-500"
                  }`}
                />
                <span className="text-slate-300 font-medium">{node.node_id.toUpperCase()}</span>
                <span className="text-slate-500 font-mono">v{node.synced_key_version}</span>
              </div>
            ))}
          </div>
        </header>

        <main className="flex-1 p-4 lg:p-6 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
};
