import React from "react";
import ReactDOM from "react-dom/client";

import "./styles.css";

function App() {
  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-mark">S</div>
        <div>
          <p className="eyebrow">SECURITY OPERATIONS PLATFORM</p>
          <h1>Sentinel Command</h1>
        </div>
        <span className="environment">DEVELOPMENT</span>
      </header>
      <section className="welcome">
        <p className="eyebrow">DETECT · ANALYSE · RESPOND · COMPLY</p>
        <h2>Security operations, unified.</h2>
        <p className="intro">
          The SOC workspace foundation is online. Authentication, tenant-aware
          data and live security telemetry will be introduced in the next phases.
        </p>
        <div className="status-row">
          <span className="status-dot" />
          Platform shell initialized
        </div>
      </section>
      <footer>Enterprise AI-Powered Cyber Security Operations Command Center</footer>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
