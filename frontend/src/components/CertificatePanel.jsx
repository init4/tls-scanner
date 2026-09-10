import React from "react";

export default function CertificatePanel({ cert }) {
  if (!cert) {
    return (
      <div className="panel">
        <h2>Certificate</h2>
        <div style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          Could not be retrieved.
        </div>
      </div>
    );
  }
  const rows = [
    ["Subject", cert.subject],
    ["Issuer", cert.issuer],
    ["Self-signed", cert.self_signed ? "yes" : "no"],
    ["Key", `${cert.key_type} / ${cert.key_bits} bits`],
    ["Signature algorithm", cert.signature_algorithm],
    ["Valid from", new Date(cert.not_before).toLocaleDateString()],
    [
      "Valid until",
      `${new Date(cert.not_after).toLocaleDateString()} (${
        cert.expired ? "EXPIRED" : `${cert.days_until_expiry}d left`
      })`,
    ],
  ];
  return (
    <div className="panel">
      <h2>Certificate</h2>
      {rows.map(([k, v]) => (
        <div className="kv-row" key={k}>
          <span className="k">{k}</span>
          <span className="v">{v}</span>
        </div>
      ))}
      {cert.sans.length > 0 && (
        <div className="kv-row">
          <span className="k">SANs</span>
          <span className="v">{cert.sans.join(", ")}</span>
        </div>
      )}
      <div style={{ marginTop: "0.6rem", color: "var(--text-muted)", fontSize: "0.78rem" }}>
        {cert.trust_note}
      </div>
    </div>
  );
}
