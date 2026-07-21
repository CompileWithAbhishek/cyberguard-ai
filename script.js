// --- Universal Heuristic Engine Logic ---
function analyzeText(inputText) {
    let riskScore = 0;
    let flags = [];

    const text = inputText.toLowerCase().trim();

    if (!text) {
        return { 
            status: "Safe", 
            riskScore: 0, 
            flags: ["No payload provided for analysis."] 
        };
    }

    // 1. URL Normalization & Domain Extraction
    let hostname = text;
    try {
        if (!text.startsWith("http://") && !text.startsWith("https://")) {
            hostname = new URL("http://" + text).hostname;
        } else {
            hostname = new URL(text).hostname;
        }
    } catch (e) {
        hostname = text.split("/")[0].split("?")[0];
    }

    // 2. Standard TLD Registry (ICANN aligned)
    const validTlds = new Set([
        "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz",
        "in", "gov.in", "co.in", "ac.in", "res.in", "uk", "us", "ca", "au"
    ]);

    const domainParts = hostname.split(".");
    
    if (domainParts.length >= 2) {
        const primaryTld = domainParts[domainParts.length - 1];
        const doubleTld = domainParts.slice(-2).join(".");

        if (!validTlds.has(primaryTld) && !validTlds.has(doubleTld)) {
            riskScore += 80;
            flags.push(`Spoofed/Invalid TLD extension: '.${primaryTld}' (Typosquatting Risk)`);
        }
    }

    // 3. Structural Anomalies Checks
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount >= 3) {
        riskScore += 25;
        flags.push(`Subdomain Stacking detected (${dotCount} dots in hostname).`);
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
        riskScore += 20;
        flags.push("High hyphen density inside domain name.");
    }

    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipPattern.test(hostname)) {
        riskScore += 85;
        flags.push("Direct IP address navigation used instead of domain name.");
    }

    // 4. Social Engineering & Phishing Keyword Triggers
    const urgentActionTriggers = [
        "verify", "urgent", "suspended", "immediate", "action required", 
        "unauthorized", "login", "password", "blocked", "expire", "claim", "refund", "kyc"
    ];

    let triggerHits = 0;
    urgentActionTriggers.forEach(word => {
        if (text.includes(word)) triggerHits++;
    });

    if (triggerHits >= 2) {
        riskScore += 35;
        flags.push(`High social engineering urgency detected (${triggerHits} flagged triggers).`);
    } else if (triggerHits === 1) {
        riskScore += 15;
        flags.push("Credential-harvesting/Panic keyword flagged.");
    }

    // 5. Final Calculation
    if (riskScore > 100) riskScore = 100;

    let status = "Safe";
    if (riskScore >= 60) {
        status = "High Threat / Phishing";
    } else if (riskScore >= 25) {
        status = "Suspicious / Caution Needed";
    }

    if (flags.length === 0) {
        flags.push("No structural anomalies or malicious indicators detected.");
    }

    return { status, riskScore, flags };
}

// --- DOM Controller & UI Handlers ---
document.addEventListener("DOMContentLoaded", () => {
    const analyzeBtn = document.getElementById("analyze-btn");
    const payloadInput = document.getElementById("payload-input");
    const resultStatus = document.getElementById("result-status");
    const resultScore = document.getElementById("result-score");
    const flagsList = document.getElementById("flags-list");
    const logTime = document.getElementById("log-time");
    const themeToggleBtn = document.getElementById("theme-toggle");

    // Theme Switcher Logic
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            document.body.classList.toggle("light-theme");
            const isLight = document.body.classList.contains("light-theme");
            themeToggleBtn.innerText = isLight ? "☀️" : "🌙";
        });
    }

    // Tab Switching UI Logic
    const tabButtons = document.querySelectorAll(".tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            tabButtons.forEach(b => {
                b.className = "px-3 py-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 tab-btn";
            });
            e.target.className = "px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold tab-btn active";
        });
    });

    // Run Dynamic Analysis
    if (analyzeBtn && payloadInput) {
        analyzeBtn.addEventListener("click", () => {
            const inputData = payloadInput.value;
            const analysis = analyzeText(inputData);

            if (resultStatus) {
                resultStatus.innerText = analysis.status;
                if (analysis.riskScore >= 60) {
                    resultStatus.className = "text-xl font-extrabold text-red-500 mt-0.5";
                } else if (analysis.riskScore >= 25) {
                    resultStatus.className = "text-xl font-extrabold text-amber-400 mt-0.5";
                } else {
                    resultStatus.className = "text-xl font-extrabold text-emerald-400 mt-0.5";
                }
            }

            if (resultScore) resultScore.innerText = `${analysis.riskScore}%`;

            if (logTime) {
                const now = new Date();
                logTime.innerText = `Log Time: ${now.toTimeString().split(' ')[0]}`;
            }

            if (flagsList) {
                flagsList.innerHTML = "";
                analysis.flags.forEach(flag => {
                    const li = document.createElement("li");
                    li.className = "text-xs text-slate-300 flex items-center gap-2 bg-slate-900/50 p-2.5 rounded-lg border border-slate-800";
                    if (analysis.riskScore > 0) {
                        li.innerHTML = `<span class="text-red-400">⚠️</span> <span class="underline decoration-red-500/80 underline-offset-4 decoration-2">${flag}</span>`;
                    } else {
                        li.innerHTML = `<span class="text-emerald-400">✓</span> <span>${flag}</span>`;
                    }
                    flagsList.appendChild(li);
                });
            }
        });
    }
});