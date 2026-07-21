// Heuristic Analysis Core Logic
function analyzeText(inputText) {
    let riskScore = 0;
    let flags = [];
    let tldValid = true;
    let isDirectIp = false;
    let subdomainCount = 0;
    let urgencyHits = 0;

    const text = inputText.toLowerCase().trim();

    if (!text) {
        return {
            status: "SAFE",
            riskScore: 0,
            flags: ["No payload provided for analysis."],
            tldValid: true,
            isDirectIp: false,
            subdomainCount: 0,
            urgencyHits: 0
        };
    }

    // Domain Parsing
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

    // Direct IP Check
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)) {
        riskScore += 85;
        isDirectIp = true;
        flags.push("Direct IP address URL used instead of a registered domain name.");
    }

    // TLD & Typosquatting Checks
    const validTlds = new Set(["com", "org", "net", "edu", "gov", "mil", "in", "gov.in", "co.in", "ac.in", "io", "co"]);
    const domainParts = hostname.split(".");
    subdomainCount = Math.max(0, domainParts.length - 2);

    if (domainParts.length >= 2) {
        const primaryTld = domainParts[domainParts.length - 1];
        if (!validTlds.has(primaryTld)) {
            riskScore += 75;
            tldValid = false;
            flags.push(`Non-standard or suspicious TLD extension detected: '.${primaryTld}'`);
        }
    }

    if (subdomainCount >= 2) {
        riskScore += 25;
        flags.push(`High subdomain depth detected (${subdomainCount} subdomains).`);
    }

    if ((hostname.match(/-/g) || []).length >= 2) {
        riskScore += 20;
        flags.push("Excessive hyphen usage inside domain name.");
    }

    // Social Engineering Keyword Matching
    const urgentWords = ["verify", "urgent", "suspended", "account", "blocked", "login", "kyc", "bank", "update", "password", "security"];
    urgentWords.forEach(word => {
        if (text.includes(word)) urgencyHits++;
    });

    if (urgencyHits >= 2) {
        riskScore += 35;
        flags.push(`Panic / Urgency social engineering keywords flagged (${urgencyHits} occurrences).`);
    } else if (urgencyHits === 1) {
        riskScore += 15;
        flags.push("Suspicious credential-harvesting trigger word found.");
    }

    if (riskScore > 100) riskScore = 100;

    let status = "SAFE";
    if (riskScore >= 60) {
        status = "CRITICAL / PHISHING";
    } else if (riskScore >= 25) {
        status = "SUSPICIOUS / WARNING";
    }

    if (flags.length === 0) {
        flags.push("No structural anomalies or malicious indicators detected.");
    }

    return { status, riskScore, flags, tldValid, isDirectIp, subdomainCount, urgencyHits };
}

// UI Controllers & Handler Bindings
document.addEventListener("DOMContentLoaded", () => {
    const payloadInput = document.getElementById("payload-input");
    const analyzeBtn = document.getElementById("analyze-btn");
    const clearBtn = document.getElementById("clear-btn");
    const samplePhish = document.getElementById("sample-phish");
    const sampleSms = document.getElementById("sample-sms");
    
    const resultStatus = document.getElementById("result-status");
    const resultScore = document.getElementById("result-score");
    const riskGauge = document.getElementById("risk-gauge");
    const riskLevelText = document.getElementById("risk-level-text");
    const flagsList = document.getElementById("flags-list");
    const logTimestamp = document.getElementById("log-timestamp");

    // Metrics Elements
    const metricTld = document.getElementById("metric-tld");
    const metricIp = document.getElementById("metric-ip");
    const metricSubdomain = document.getElementById("metric-subdomain");
    const metricUrgency = document.getElementById("metric-urgency");
    const copyLogBtn = document.getElementById("copy-log-btn");

    // Quick Sample Handlers
    if (samplePhish) {
        samplePhish.addEventListener("click", () => {
            payloadInput.value = "http://login-verify-account.pgportal.govv.in/secure/auth.php";
        });
    }

    if (sampleSms) {
        sampleSms.addEventListener("click", () => {
            payloadInput.value = "URGENT: Your SBI Account is blocked today. Click http://192.168.1.45/verify to update KYC immediately.";
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            payloadInput.value = "";
        });
    }

    // Core Analysis Trigger
    if (analyzeBtn && payloadInput) {
        analyzeBtn.addEventListener("click", () => {
            const data = analyzeText(payloadInput.value);

            // Status Update
            resultStatus.innerText = data.status;
            if (data.riskScore >= 60) {
                resultStatus.className = "text-xl sm:text-2xl font-black text-red-500 mt-1";
                riskGauge.className = "bg-red-500 h-full rounded-full transition-all duration-500";
                riskLevelText.innerText = "CRITICAL RISK";
            } else if (data.riskScore >= 25) {
                resultStatus.className = "text-xl sm:text-2xl font-black text-amber-400 mt-1";
                riskGauge.className = "bg-amber-400 h-full rounded-full transition-all duration-500";
                riskLevelText.innerText = "MODERATE RISK";
            } else {
                resultStatus.className = "text-xl sm:text-2xl font-black text-emerald-400 mt-1";
                riskGauge.className = "bg-emerald-500 h-full rounded-full transition-all duration-500";
                riskLevelText.innerText = "LOW RISK";
            }

            resultScore.innerText = `${data.riskScore}%`;
            riskGauge.style.width = `${data.riskScore}%`;

            // Metrics Update
            metricTld.innerText = data.tldValid ? "VALID" : "INVALID / SPOOF";
            metricTld.className = data.tldValid ? "text-emerald-400 font-bold" : "text-red-400 font-bold";

            metricIp.innerText = data.isDirectIp ? "DETECTED" : "NONE";
            metricIp.className = data.isDirectIp ? "text-red-400 font-bold" : "text-emerald-400 font-bold";

            metricSubdomain.innerText = `${data.subdomainCount} DEPTH`;
            metricUrgency.innerText = `${data.urgencyHits} MATCHES`;

            // Timestamp
            const now = new Date();
            logTimestamp.innerText = `Timestamp: ${now.toTimeString().split(' ')[0]}`;

            // Render Diagnostic Logs
            flagsList.innerHTML = "";
            data.flags.forEach(flag => {
                const li = document.createElement("li");
                li.className = "text-xs text-slate-300 flex items-center space-x-2 bg-slate-950/50 p-3 rounded-xl border border-slate-800";
                if (data.riskScore > 0) {
                    li.innerHTML = `<span class="text-red-400"><i class="fa-solid fa-triangle-exclamation"></i></span> <span>${flag}</span>`;
                } else {
                    li.innerHTML = `<span class="text-emerald-400"><i class="fa-solid fa-circle-check"></i></span> <span>${flag}</span>`;
                }
                flagsList.appendChild(li);
            });
        });
    }

    // Copy Log Functionality
    if (copyLogBtn) {
        copyLogBtn.addEventListener("click", () => {
            const reportText = `[CyberGuard AI Report]\nThreat Status: ${resultStatus.innerText}\nRisk Index: ${resultScore.innerText}\nInput: ${payloadInput.value}`;
            navigator.clipboard.writeText(reportText);
            copyLogBtn.innerText = "Copied!";
            setTimeout(() => {
                copyLogBtn.innerText = "Copy Report";
            }, 2000);
        });
    }
});