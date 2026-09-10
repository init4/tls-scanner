import React from "react";

const KIND_LABEL = {
  "hybrid-final": "ML-KEM (standardized)",
  "hybrid-draft": "Kyber (draft, legacy)",
  classical: "classical",
};

export default function PqcGroupsPanel({ groups }) {
  return (
    <div className="panel">
      <h2>Key-exchange groups</h2>
      {groups.map((g) => (
        <div className="protocol-row" key={g.name}>
          <span>
            <span
              className={`dot ${
                g.supported === true ? "ok" : g.supported === false ? "bad" : "unknown"
              }`}
            />
            {g.name}
            <span style={{ color: "var(--text-muted)", marginLeft: "0.5rem", fontSize: "0.75rem" }}>
              {KIND_LABEL[g.kind]}
            </span>
          </span>
          <span style={{ color: "var(--text-muted)", fontSize: "0.78rem", textAlign: "right" }}>
            {g.supported === true ? "negotiated" : g.supported === false ? "not negotiated" : g.note || "untestable"}
          </span>
        </div>
      ))}
    </div>
  );
}
