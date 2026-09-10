import React from "react";

export default function ProtocolTable({ protocols }) {
  return (
    <div className="panel">
      <h2>Protocol support</h2>
      {protocols.map((p) => (
        <div className="protocol-row" key={p.name}>
          <span>
            <span
              className={`dot ${
                p.supported === true ? "ok" : p.supported === false ? "bad" : "unknown"
              }`}
            />
            {p.name}
          </span>
          <span style={{ color: "var(--text-muted)" }}>
            {p.supported === true ? "supported" : p.supported === false ? "not supported" : "not tested"}
          </span>
        </div>
      ))}
    </div>
  );
}
