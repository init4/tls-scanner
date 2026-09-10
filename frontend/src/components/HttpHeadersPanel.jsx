import React from "react";

export default function HttpHeadersPanel({ headers, score, label }) {
  if (!headers || !headers.checked) {
    return (
      <div className="panel">
        <h2>HTTP security headers</h2>
        <div style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          {headers?.note || "Could not be checked."}
        </div>
      </div>
    );
  }
  return (
    <div className="panel">
      <h2>
        HTTP security headers
        <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: "0.5rem" }}>
          &middot; {score}/100 &middot; {label}
        </span>
      </h2>
      {headers.headers.map((h) => (
        <div className="protocol-row" key={h.header}>
          <span>
            <span className={`dot ${h.present ? "ok" : h.note ? "ok" : "bad"}`} />
            {h.header}
          </span>
          <span style={{ color: "var(--text-muted)", fontSize: "0.78rem", textAlign: "right", maxWidth: "60%" }}>
            {h.present ? h.value : h.note || "not set"}
          </span>
        </div>
      ))}
    </div>
  );
}
