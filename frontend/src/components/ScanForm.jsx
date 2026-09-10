import React, { useState } from "react";

export default function ScanForm({ onScan, loading }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState(443);
  const [sni, setSni] = useState("");

  function submit(e) {
    e.preventDefault();
    if (!host.trim()) return;
    onScan({ host: host.trim(), port, sni: sni.trim() });
  }

  return (
    <form className="scan-form" onSubmit={submit}>
      <input
        className="host"
        placeholder="host or IP, e.g. 10.0.4.12 or vault.internal"
        value={host}
        onChange={(e) => setHost(e.target.value)}
        spellCheck={false}
        autoFocus
      />
      <input
        className="port"
        type="number"
        min={1}
        max={65535}
        value={port}
        onChange={(e) => setPort(e.target.value)}
      />
      <input
        className="sni"
        placeholder="SNI override (optional)"
        value={sni}
        onChange={(e) => setSni(e.target.value)}
        spellCheck={false}
      />
      <button type="submit" disabled={loading}>
        {loading ? "scanning…" : "run scan"}
      </button>
      <div className="form-hint">
        Certificate verification is intentionally disabled -- this tool is built to reach bare IPs and
        self-signed/untrusted endpoints and report on what it finds, not to reject them.
      </div>
    </form>
  );
}
