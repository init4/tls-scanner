import React from "react";

// `supported` means "the thing this check looks for is present on the
// server" -- for secure_renegotiation/fallback_scsv that's the *good*
// outcome (a protection is present), but for tls_compression it's the
// *bad* outcome (the CRIME-enabling behavior is present). goodWhenSupported
// lets the dot color track "is this good for the server" rather than just
// mirroring the raw boolean.
const CHECK_META = {
  secure_renegotiation: { label: "Secure renegotiation (RFC 5746)", goodWhenSupported: true },
  tls_compression: { label: "TLS compression (CRIME)", goodWhenSupported: false },
  fallback_scsv: { label: "Downgrade guard (TLS_FALLBACK_SCSV)", goodWhenSupported: true },
};

function dotClass(supported, goodWhenSupported) {
  if (supported === null || supported === undefined) return "unknown";
  return supported === goodWhenSupported ? "ok" : "bad";
}

export default function LegacyChecksPanel({ checks }) {
  return (
    <div className="panel">
      <h2>Downgrade &amp; legacy checks</h2>
      {checks.map((c) => {
        const meta = CHECK_META[c.name] || { label: c.name, goodWhenSupported: true };
        return (
          <div className="protocol-row" key={c.name}>
            <span>
              <span className={`dot ${dotClass(c.supported, meta.goodWhenSupported)}`} />
              {meta.label}
            </span>
            <span style={{ color: "var(--text-muted)", fontSize: "0.78rem", textAlign: "right" }}>
              {c.supported === true ? "present" : c.supported === false ? "absent" : "untestable"}
            </span>
          </div>
        );
      })}
    </div>
  );
}
