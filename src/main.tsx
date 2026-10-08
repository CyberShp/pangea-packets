import React from "react";
import ReactDOM from "react-dom/client";
import App from "./Platform";
import "./index.css";
import "./api-integration.css";
import "./packet-flow.css";
import "./packet-theme.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
