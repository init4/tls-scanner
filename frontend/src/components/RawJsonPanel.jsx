import React, { useState } from "react";

export default function RawJsonPanel({ data }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel full-span">
      <h2 style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        Raw JSON
        <button className="toggle-link" onClick={() => setOpen((o) => !o)}>
          {open ? "hide" : "show"}
        </button>
      </h2>
      {open && <pre className="raw-json">{JSON.stringify(data, null, 2)}</pre>}
    </div>
  );
}
