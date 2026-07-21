function analyzeText(inputText) {
    let riskScore = 0;
    let flags = [];

    const text = inputText.toLowerCase().trim();

    if (!text) {
        return { 
            status: "Safe", 
            riskScore: 0, 
            flags: ["No text or payload provided for analysis."] 
        };
    }

    // Clean URL string to isolate domain name
    let domainStr = text.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0];

    const repeatedTldPattern = /\.(gov|com|org|net|edu|in|co)[a-z]{1,2}$/i;
    const exactStandardTlds = ["gov", "com", "org", "net", "edu", "in", "gov.in", "co.in"];
    
    const parts = domainStr.split('.');
    if (parts.length >= 2) {
        const lastPart = parts[parts.length - 1];
        const combinedTld = parts.slice(-2).join('.');
        
        if (!exactStandardTlds.includes(lastPart) && !exactStandardTlds.includes(combinedTld)) {
            if (repeatedTldPattern.test(domainStr) || lastPart.length > 3) {
                riskScore += 85;
                flags.push(`Suspicious/Spoofed TLD extension detected: '.${lastPart}' (Typosquatting Risk).`);
            }
        }
    }

    const l33tPattern = /([a-z0-9_-]+)\.(g[0o]v|c[0o]m|0rg|[a-z0-9-]{12,})/i;
    if (l33tPattern.test(text) && !text.includes("http://") && !text.includes("https://")) {
        riskScore += 30;
        flags.push("Homograph/Character Substitution risk (L33t speak or character spoofing detected).");
    }

    const dotCount = (domainStr.match(/\./g) || []).length;
    if (dotCount >= 3) {
        riskScore += 25;
        flags.push(`Excessive subdomains detected (${dotCount} dots). Common in obfuscated phishing links.`);
    }

    const hyphenCount = (domainStr.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
        riskScore += 20;
        flags.push("High hyphen density in hostname (frequently used to imitate legitimate domains).");
    }

    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    if (ipPattern.test(text)) {
        riskScore += 80;
        flags.push("Direct IP address navigation detected instead of a registered domain name.");
    }

    const urgentActionTriggers = [
        "verify", "urgent", "suspended", "immediate", "action required", 
        "unauthorized", "login", "password", "blocked", "expire", "claim", "refund", "kyc"
    ];

    let triggerHits = 0;
    urgentActionTriggers.forEach(word => {
        if (text.includes(word)) {
            triggerHits++;
        }
    });

    if (triggerHits >= 2) {
        riskScore += 35;
        flags.push(`High social engineering urgency detected (${triggerHits} action keywords flagged).`);
    } else if (triggerHits === 1) {
        riskScore += 15;
        flags.push("Contains common credential-harvesting keyword.");
    }

    if (riskScore > 100) riskScore = 100;

    let status = "Safe";
    if (riskScore >= 60) {
        status = "High Threat / Phishing";
    } else if (riskScore >= 25) {
        status = "Suspicious / Caution Needed";
    }

    if (flags.length === 0) {
        flags.push("No suspicious structural anomalies or threat patterns detected.");
    }

    return { status, riskScore, flags };
}

function checkPasswordStrength(password) {
    let score = 0;
    let feedback = [];

    if (!password) {
        return { score: 0, status: "Empty", feedback: ["Please enter a password."] };
    }

    if (password.length >= 8) score += 25;
    else feedback.push("Password length should be at least 8 characters.");

    if (/[A-Z]/.test(password)) score += 25;
    else feedback.push("Include at least one uppercase letter (A-Z).");

    if (/[0-9]/.test(password)) score += 25;
    else feedback.push("Include at least one numerical digit (0-9).");

    if (/[^A-Za-z0-9]/.test(password)) score += 25;
    else feedback.push("Include at least one special character (!@#$%^&*).");

    let status = "Weak";
    if (score >= 75) status = "Strong";
    else if (score >= 50) status = "Moderate";

    return { score, status, feedback };
}

document.addEventListener("DOMContentLoaded", () => {
    const analyzeBtn = document.getElementById("analyze-btn");
    const payloadInput = document.getElementById("payload-input");
    const resultStatus = document.getElementById("result-status");
    const resultScore = document.getElementById("result-score");
    const flagsList = document.getElementById("flags-list");
    const logTime = document.getElementById("log-time");

    if (analyzeBtn && payloadInput) {
        analyzeBtn.addEventListener("click", () => {
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
                    li.innerHTML = `<span class="text-amber-400">⚠️</span> <span class="underline decoration-red-500 decoration-2 underline-offset-4">${flag}</span>`;
                    flagsList.appendChild(li);
                });
            }
        });
    }

    const passInput = document.getElementById("password-input");
    const passScore = document.getElementById("password-score");
    const passStatus = document.getElementById("password-status");

    if (passInput) {
        passInput.addEventListener("input", (e) => {
            const result = checkPasswordStrength(e.target.value);
            if (passScore) passScore.innerText = `${result.score}%`;
            if (passStatus) passStatus.innerText = result.status;
        });
    }
});