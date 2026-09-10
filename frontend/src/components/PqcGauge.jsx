import React from "react";

// A radial dial for PQC readiness -- deliberately distinct from the
// classic A-F badge used for the headline grade, since "readiness for
// a future migration" is a different kind of signal than "graded pass/fail".
export default function PqcGauge({ score, label }) {
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - pct / 100);

  const color =
    pct >= 60 ? "var(--accent-lattice)" : pct > 0 ? "var(--accent-warn)" : "var(--text-muted)";

  return (
    <div className="pqc-gauge-wrap">
      <svg width="76" height="76" viewBox="0 0 76 76">
        <circle
          cx="38"
          cy="38"
          r={radius}
          fill="none"
          stroke="var(--hairline)"
          strokeWidth="7"
        />
        <circle
          cx="38"
          cy="38"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 38 38)"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        <text
          x="38"
          y="43"
          textAnchor="middle"
          fontFamily="IBM Plex Mono, monospace"
          fontSize="18"
          fontWeight="600"
          fill="var(--text-primary)"
        >
          {pct}
        </text>
      </svg>
      <div>
        <div className="pqc-gauge-label">PQC readiness</div>
        <div className="pqc-gauge-sub">{label}</div>
      </div>
    </div>
  );
}
