import React, { useEffect, useState } from "react";
import { Lock, Send, ShieldAlert, ShieldCheck } from "lucide-react";
import { apiRequest } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { DemoAccount, SecureMessage } from "../types";

interface Props {
  token: string;
  deviceId: string | null;
  currentUserId: string;
}

export const MessagesPage: React.FC<Props> = ({ token, deviceId, currentUserId }) => {
  const [messages, setMessages] = useState<SecureMessage[]>([]);
  const [recipients, setRecipients] = useState<DemoAccount[]>([]);
  const [recipientId, setRecipientId] = useState("usr-alice");
  const [plaintext, setPlaintext] = useState("");
  const [lastEnvelope, setLastEnvelope] = useState<Record<string, any> | null>(null);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  const loadData = async () => {
    try {
      const [msgs, accs] = await Promise.all([
        apiRequest<SecureMessage[]>("/api/messages", { token, deviceId }),
        apiRequest<DemoAccount[]>("/api/auth/demo-accounts"),
      ]);
      setMessages(msgs);
      const others = accs.filter((a) => a.user_id !== currentUserId);
      setRecipients(others.length > 0 ? others : accs);
      if (others.length > 0 && !others.some((o) => o.user_id === recipientId)) {
        setRecipientId(others[0].user_id);
      }
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  useEffect(() => {
    loadData();
  }, [token, deviceId, currentUserId]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    try {
      const res = await apiRequest<{ delivery: any; envelope: any }>("/api/messages/send", {
        method: "POST",
        token,
        deviceId,
        body: { recipient_id: recipientId, plaintext },
      });
      setLastEnvelope(res.envelope);
      setPlaintext("");
      setFeedback({
        type: "ok",
        msg: `Message ${res.delivery.message_id} encrypted (ML-KEM-768 + AES-256-GCM), signed (ML-DSA-65), verified, and delivered. Ephemeral session key zeroized.`,
      });
      await loadData();
    } catch (err: any) {
      setFeedback({ type: "err", msg: err.message });
    }
  };

  const handleReplayTest = async () => {
    if (!lastEnvelope) return;
    setFeedback(null);
    try {
      await apiRequest("/api/messages/deliver-envelope", {
        method: "POST",
        token,
        deviceId,
        body: { envelope: lastEnvelope },
      });
      setFeedback({ type: "ok", msg: "Unexpectedly accepted replay." });
    } catch (err: any) {
      setFeedback({ type: "err", msg: `Replay Test Result: ${err.message}` });
    }
  };

  const handleAlterRecipientTest = async () => {
    if (!lastEnvelope) return;
    setFeedback(null);
    const altRecipient =
      recipients.find((r) => r.user_id !== lastEnvelope.recipient_id)?.user_id ?? "usr-carol";
    const altered = {
      ...lastEnvelope,
      message_id: `msg-tamper-${Date.now().toString(36)}`,
      recipient_id: altRecipient,
    };
    try {
      await apiRequest("/api/messages/deliver-envelope", {
        method: "POST",
        token,
        deviceId,
        body: { envelope: altered },
      });
    } catch (err: any) {
      setFeedback({ type: "err", msg: `Tampered Recipient Test Result: ${err.message}` });
    }
  };

  const handleIncompleteTest = async () => {
    setFeedback(null);
    try {
      await apiRequest("/api/messages/deliver-envelope", {
        method: "POST",
        token,
        deviceId,
        body: { envelope: { message_id: "msg-incomplete-test", sender_id: currentUserId } },
      });
    } catch (err: any) {
      setFeedback({ type: "err", msg: `Incomplete Envelope Test Result: ${err.message}` });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Post-Quantum Secure Messaging</h1>
        <p className="text-sm text-slate-400">
          Ephemeral ML-KEM-768 forward secrecy, HKDF-SHA256 + AES-256-GCM AAD recipient binding, ML-DSA-65 sender authentication, and replay rejection.
        </p>
      </div>

      {/* Forward Secrecy Explanation */}
      <div className="p-4 rounded-xl bg-cyan-500/5 border border-cyan-500/25 text-xs text-slate-300 space-y-1">
        <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
          <Lock className="w-3.5 h-3.5" />
          Forward Secrecy Session Architecture & Security Assumptions
        </div>
        <p>
          Static long-term KEM keys alone do not guarantee forward secrecy. TrustGuard generates a fresh, one-time{" "}
          <span className="font-mono text-white">ML-KEM-768</span> ephemeral keypair per message session in volatile memory, binds sender, recipient, and{" "}
          <span className="font-mono text-white">message_id</span> into AES-256-GCM AAD + HKDF context, signs with{" "}
          <span className="font-mono text-white">ML-DSA-65</span>, and zeroizes the ephemeral secret key immediately upon delivery. Compromising long-term identity signing keys later cannot decrypt past ephemeral sessions (assuming ephemeral RAM was not captured during the brief active window).
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <form
          onSubmit={handleSend}
          className="lg:col-span-2 p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Send className="w-4 h-4 text-cyan-400" />
            Send Authenticated PQC Message
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Intended Recipient</label>
            <select
              value={recipientId}
              onChange={(e) => setRecipientId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            >
              {recipients.map((r) => (
                <option key={r.user_id} value={r.user_id}>
                  {r.username} ({r.role}) — {r.full_name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Confidential Message</label>
            <textarea
              required
              rows={3}
              value={plaintext}
              onChange={(e) => setPlaintext(e.target.value)}
              placeholder="Enter confidential operational message..."
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium"
          >
            Encrypt, Sign & Deliver
          </button>
        </form>

        {/* Security Verification Lab */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            Delivery Gate Security Tests
          </div>
          <p className="text-xs text-slate-400">
            Send a message first, then verify that the backend delivery gate rejects replay, altered recipients, and incomplete envelopes.
          </p>
          <button
            onClick={handleReplayTest}
            disabled={!lastEnvelope}
            className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-xs font-medium text-amber-300 border border-slate-700"
          >
            Replay Last Message ID (Expect Reject)
          </button>
          <button
            onClick={handleAlterRecipientTest}
            disabled={!lastEnvelope}
            className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-xs font-medium text-rose-300 border border-slate-700"
          >
            Alter Recipient on Envelope (Expect Reject)
          </button>
          <button
            onClick={handleIncompleteTest}
            className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-orange-300 border border-slate-700"
          >
            Send Incomplete Envelope (Expect Reject)
          </button>
        </div>
      </div>

      {/* Messages Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-white">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Verified Messages (Plaintext visible only to intended recipient)
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono">
              <tr>
                <th className="px-4 py-3">Message / Session</th>
                <th className="px-4 py-3">Sender → Recipient</th>
                <th className="px-4 py-3">PQC Suite</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Content / Sealed Ciphertext</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {messages.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-slate-400">
                    No messages delivered yet. Send a confidential message above.
                  </td>
                </tr>
              ) : (
                messages.map((m) => (
                  <tr key={m.message_id}>
                    <td className="px-4 py-3 font-mono">
                      <div className="text-cyan-300">{m.message_id}</div>
                      <div className="text-slate-500">{m.session_id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-white">{m.sender_username}</span> →{" "}
                      <span className="text-emerald-300">{m.recipient_username}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">
                      {m.kem_algorithm} + {m.sig_algorithm} (v{m.signing_key_version})
                    </td>
                    <td className="px-4 py-3 space-y-1">
                      <StatusBadge value={m.delivery_status} />
                      {m.forward_secret && (
                        <div className="text-[10px] font-mono text-cyan-400">EPHEMERAL FS</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {m.plaintext ? (
                        <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-200">
                          {m.plaintext}
                        </div>
                      ) : (
                        <div className="font-mono text-slate-500">
                          [Sealed for {m.recipient_username}] {m.ciphertext_preview}
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
