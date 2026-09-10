import React from "react";

export default function CipherList({ ciphers }) {
  const supported = ciphers.filter((c) => c.supported);
  const byProtocol = supported.reduce((acc, c) => {
    (acc[c.protocol] ||= []).push(c);
    return acc;
  }, {});

  const order = ["strong", "acceptable", "weak", "insecure"];
  for (const list of Object.values(byProtocol)) {
    list.sort((a, b) => order.indexOf(a.strength) - order.indexOf(b.strength));
  }

  return (
    <div className="panel">
      <h2>Negotiable cipher suites</h2>
      {Object.keys(byProtocol).length === 0 && (
        <div style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          None of the candidate suites this scanner tried were accepted.
        </div>
      )}
      {Object.entries(byProtocol).map(([proto, list]) => (
        <div key={proto}>
          <div className="cipher-group-title">{proto}</div>
          <div className="cipher-chip-row">
            {list.map((c) => (
              <span key={c.name} className={`cipher-chip ${c.strength}`} title={c.strength}>
                {c.name}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
