import React from "react";

const ORDER = ["critical", "high", "medium", "low", "info"];

export default function FindingsList({ findings }) {
  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  return (
    <div className="panel full-span">
      <h2>Findings</h2>
      {sorted.map((f, i) => (
        <div className="finding" key={i}>
          <span className={`sev sev-${f.severity}`}>{f.severity}</span>
          <span>{f.message}</span>
        </div>
      ))}
    </div>
  );
}
