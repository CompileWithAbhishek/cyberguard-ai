function analyzeText(inputText) {
    let riskScore = 0;
    let flags = [];

    const text = (inputText || "").toLowerCase().trim();

    if (!text) {
        return { 
            status: "Safe", 
            riskScore: 0, 
            flags: ["No threat flags discovered inside target string lines."] 
        };
    }

    // Isolate hostname/domain part safely
    let domainStr = text.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0];

    // Detect typosquatting in government & generic TLDs
    const fakeGovPattern = /(govv|gov-|\.gov\.[a-z]{2,3}\.[a-z]{2}|goov|g0v)/i;
    if (fakeGovPattern.test(domainStr) || domainStr.includes(".govv")) {
        riskScore += 85;
        flags.push("Detected fake/spoofed government domain pattern (Typosquatting).");
    }

    const repeatedTldPattern = /\.(gov|com|org|net|edu|in|co)[a-z]{1,2}$/i;
    const exactStandardTlds = ["gov", "com", "org", "net", "edu", "in", "gov.in", "co.in"];
    
    const parts = domainStr.split('.');
    if (parts.length >= 2) {
        const lastPart = parts[parts.length - 1];
        const combinedTld = parts.slice(-2).join('.');
        
        if (!exactStandardTlds.includes(lastPart) && !exactStandardTlds.includes(combinedTld)) {
            if (repeatedTldPattern.test(domainStr) || lastPart.length > 3) {
                riskScore += 80;
                flags.push(`Suspicious/Spoofed TLD extension detected: '.${lastPart}'.`);
            }
        }
    }

    // IP Navigation Check
    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    if (ipPattern.test(text)) {
        riskScore += 80;
        flags.push("Direct IP address navigation detected instead of a registered domain name.");
    }

    // Social engineering urgency
    const urgentActionTriggers = ["verify", "urgent", "suspended", "login", "password", "blocked", "claim", "kyc"];
    let triggerHits = 0;
    urgentActionTriggers.forEach(word => {
        if (text.includes(word)) triggerHits++;
    });

    if (triggerHits >= 2) {
        riskScore += 30;
        flags.push(`High social engineering urgency detected (${triggerHits} action keywords flagged).`);
    }

    if (riskScore > 100) riskScore = 100;

    let status = "Safe";
    if (riskScore >= 60) {
        status = "High Threat / Phishing";
    } else if (riskScore >= 25) {
        status = "Suspicious / Caution";
    }

    if (flags.length === 0) {
        flags.push("No threat flags discovered inside target string lines.");
    }

    return { status, riskScore, flags };
}

// Global initialization & event binding
document.addEventListener("DOMContentLoaded", () => {
    // Multi-selector binding to support different HTML element IDs
    const analyzeBtn = document.getElementById("analyze-btn") || document.querySelector("button");
    const payloadInput = document.getElementById("payload-input") || document.querySelector("textarea") || document.querySelector("input[type='text']");
    const resultStatus = document.getElementById("result-status") || document.querySelector(".status-text");
    const resultScore = document.getElementById("result-score") || document.querySelector(".score-text");
    const flagsList = document.getElementById("flags-list") || document.querySelector("ul");
    const logTime = document.getElementById("log-time");

    function runAnalysis() {
        if (!payloadInput) return;
        const inputData = payloadInput.value;
        const analysis = analyzeText(inputData);

        if (resultStatus) resultStatus.innerText = analysis.status;
        if (resultScore) resultScore.innerText = `${analysis.riskScore}%`;

        if (logTime) {
            const now = new Date();
            logTime.innerText = `Log Time: ${now.toTimeString().split(' ')[0]}`;
        }

        if (flagsList) {
            flagsList.innerHTML = "";
            analysis.flags.forEach(flag => {
                const li = document.createElement("li");
                li.className = "text-sm my-1 flex items-center gap-2 text-slate-300";
                li.innerHTML = `<span>⚠️</span> <span class="underline decoration-red-500 decoration-2 underline-offset-4">${flag}</span>`;
                flagsList.appendChild(li);
            });
        }
    }

    if (analyzeBtn) {
        analyzeBtn.addEventListener("click", runAnalysis);
    }
});