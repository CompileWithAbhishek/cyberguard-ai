# 🛡️ CyberGuard AI – Universal Threat Inspector & Phishing Sandbox

An enterprise-grade, client-side cybersecurity sandbox designed to analyze suspicious payloads, phishing URLs, domain spoofing, and malicious communication templates using universal heuristics and ICANN-aligned validation engines.

![CyberGuard AI](https://img.shields.io/badge/Security-Sandbox-cyan?style=for-the-badge&logo=shield)
![JavaScript](https://img.shields.io/badge/Engine-Vanilla%20JS-yellow?style=for-the-badge&logo=javascript)
![Tailwind CSS](https://img.shields.io/badge/UI-Tailwind%20CSS-blue?style=for-the-badge&logo=tailwindcss)

---

## ✨ Key Features

- **🌐 Universal Heuristic Detection:** Eliminates static hardcoded rules in favor of dynamic URL parsing and structure analysis.
- **🏷️ ICANN-Aligned TLD Registry:** Flags non-standard, spoofed, or typosquatted Top-Level Domains (TLDs) instantly.
- **🔍 Anomaly Inspection:** Detects direct IP navigation, excessive subdomain stacking, hyphen abuse, and character substitutions.
- **⚡ Zero-Server Isolation:** Executes all heuristic passes client-side for immediate threat evaluation with complete privacy.
- **🎨 Glassmorphic Responsive UI:** Fully responsive layout with custom themes (Light / Dark mode toggle) and low-latency interaction.

---

## 🚀 Tech Stack

- **Frontend:** HTML5, Tailwind CSS, Custom Utility CSS
- **Engine Logic:** Modern Vanilla JavaScript (ES6+)
- **Deployment:** GitHub Pages

---

## 🛠️ How It Works

1. **Input Normalization:** Strips raw payload inputs and safely parses target URLs via built-in API interfaces.
2. **Registry Verification:** Validates primary and secondary TLDs against official domain extensions.
3. **Behavioral Flags:** Evaluates panic-inducing social engineering keywords and domain structure risks.
4. **Risk Score Assignment:** Computes an aggregated risk index (`0% - 100%`) with explicit diagnostic logs.

---

## 👤 Author

Developed by **[CompileWithAbhishek](https://github.com/CompileWithAbhishek)**.