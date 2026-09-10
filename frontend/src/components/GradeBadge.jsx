import React from "react";

export default function GradeBadge({ grade }) {
  const cls = grade === "A+" ? "grade-Ap" : `grade-${grade}`;
  return <div className={`grade-badge ${cls}`}>{grade}</div>;
}
