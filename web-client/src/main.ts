import "./styles.css";
import { CONFIG } from "./config.js";

console.log(
  "%cCYBERDECK%c initializing...",
  "color: #00f0ff; font-weight: bold; font-size: 14px;",
  "color: #c0d0e0;",
  CONFIG.MOCK_MODE ? "(mock mode)" : "(live)",
);
