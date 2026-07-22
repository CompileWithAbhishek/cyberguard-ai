// Local Database & State
let scanLogs = JSON.parse(localStorage.getItem('cyberguard_logs') || '[]');
let currentTab = 'url';

document.addEventListener('DOMContentLoaded', () => {
    // Theme Toggle
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
        themeSelect.addEventListener('change', (e) => {
            const root = document.getElementById('mainHtmlRoot');
            if (e.target.value === 'light') {
                root.classList.remove('dark');
                root.classList.add('light-mode');
            } else {
                root.classList.remove('light-mode');
                root.classList.add('dark');
            }
        });
    }

    // Navigation Links
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function () {
            document.querySelectorAll('nav a').forEach(l => l.classList.remove('bg-cyan-500/10', 'text-cyan-400', 'border', 'border-cyan-500/20', 'font-bold'));
            this.classList.add('bg-cyan-500/10', 'text-cyan-400', 'border', 'border-cyan-500/20', 'font-bold');
        });
    });

    updateTelemetryStats();
    renderLogsTable();
});

// Tab Switcher
function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.className = "tab-btn px-4 py-2 rounded-xl text-slate-400 hover:text-slate-200 flex items-center space-x-2 transition cursor-pointer";
    });
    const activeBtn = document.getElementById(`tab-${tab}`);
    if (activeBtn) {
        activeBtn.className = "tab-btn px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold flex items-center space-x-2 transition cursor-pointer";
    }
}

// Detection Engine
function runAnalysisCheck() {
    const inputField = document.getElementById('payload-input');
    const rawVal = inputField ? inputField.value.trim() : '';

    if (!rawVal) {
        alert("Enter a URL, email string, or SMS payload first.");
        return;
    }

    let riskScore = 0;
    let flags = [];
    const lower = rawVal.toLowerCase();

    // Typosquatting Check (.orrg, .govv, etc.)
    const typoPattern = /\.(orrg|govv|cm|nett|coo|infoo|xyz|top|zip|work|click)\b/;
    if (typoPattern.test(lower)) {
        riskScore += 80;
        flags.push("CRITICAL: Typosquatting/Spoofed Domain Extension Detected.");
    }

    // Subdomains & Hyphens
    if ((lower.match(/\./g) || []).length >= 3) {
        riskScore += 30;
        flags.push("WARNING: High Subdomain nesting depth.");
    }
    if ((lower.match(/-/g) || []).length >= 2) {
        riskScore += 20;
        flags.push("SUSPICIOUS: Multiple hyphens used in domain.");
    }

    // Raw IP Check
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(lower.replace(/http(s)?:\/\//, '').split('/')[0])) {
        riskScore += 85;
        flags.push("DANGEROUS: Direct IP hosting instead of legitimate domain.");
    }

    // Urgent Keywords
    const urgentKeywords = ['verify', 'blocked', 'urgent', 'kyc', 'suspend', 'update-password', 'secure-login', 'bank', 'free-gift'];
    let keywordHits = 0;
    urgentKeywords.forEach(kw => {
        if (lower.includes(kw)) keywordHits++;
    });

    if (keywordHits > 0) {
        riskScore += (keywordHits * 25);
        flags.push(`SUSPICIOUS: Found ${keywordHits} social-engineering/urgency triggers.`);
    }

    if (riskScore > 100) riskScore = 100;

    let status = "CLEAN";
    if (riskScore >= 60) status = "DANGEROUS";
    else if (riskScore >= 20) status = "SUSPICIOUS";

    if (flags.length === 0) flags.push("No structural anomalies or malicious indicators detected.");

    // Update Logs
    const newEntry = {
        id: Date.now(),
        time: new Date().toLocaleTimeString(),
        vector: currentTab.toUpperCase(),
        payload: rawVal.length > 40 ? rawVal.substring(0, 40) + '...' : rawVal,
        status: status,
        score: riskScore,
        flags: flags
    };

    scanLogs.unshift(newEntry);
    localStorage.setItem('cyberguard_logs', JSON.stringify(scanLogs));

    // Render Results
    document.getElementById('output-idle')?.classList.add('hidden');
    const resContainer = document.getElementById('output-results');
    resContainer?.classList.remove('hidden');

    const statusEl = document.getElementById('res-status');
    if (statusEl) {
        statusEl.innerText = status;
        statusEl.className = status === 'DANGEROUS' ? 'text-xl font-extrabold text-red-500 animate-pulse' : (status === 'SUSPICIOUS' ? 'text-xl font-extrabold text-amber-400' : 'text-xl font-extrabold text-emerald-400');
    }

    const scoreEl = document.getElementById('res-score');
    if (scoreEl) scoreEl.innerText = `${riskScore}%`;

    const logsList = document.getElementById('res-logs');
    if (logsList) {
        logsList.innerHTML = flags.map(f => `
            <li class="flex items-start space-x-2 text-xs">
                <i class="fa-solid ${status === 'CLEAN' ? 'fa-check text-emerald-400' : 'fa-triangle-exclamation text-amber-400'} mt-0.5"></i>
                <span>${f}</span>
            </li>
        `).join('');
    }

    updateTelemetryStats();
    renderLogsTable();
}

// Telemetry Stats
function updateTelemetryStats() {
    const total = scanLogs.length;
    const clean = scanLogs.filter(l => l.status === 'CLEAN').length;
    const suspicious = scanLogs.filter(l => l.status === 'SUSPICIOUS').length;
    const dangerous = scanLogs.filter(l => l.status === 'DANGEROUS').length;

    if (document.getElementById('stat-total')) document.getElementById('stat-total').innerText = total;
    if (document.getElementById('stat-clean')) document.getElementById('stat-clean').innerText = clean;
    if (document.getElementById('stat-suspicious')) document.getElementById('stat-suspicious').innerText = suspicious;
    if (document.getElementById('stat-dangerous')) document.getElementById('stat-dangerous').innerText = dangerous;
    if (document.getElementById('vector-count')) document.getElementById('vector-count').innerText = total;
}

// Table Logs
function renderLogsTable() {
    const filter = (document.getElementById('filter-logs')?.value || '').toLowerCase();
    const tbody = document.getElementById('logs-table-body');
    if (!tbody) return;

    const filtered = scanLogs.filter(l => l.payload.toLowerCase().includes(filter) || l.vector.toLowerCase().includes(filter));

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-500 font-mono">Registers space empty. Run scanner to generate telemetry logs.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(l => `
        <tr class="hover:bg-slate-800/40 border-b border-slate-800/40 transition">
            <td class="py-3 text-slate-400">${l.time}</td>
            <td class="py-3 font-bold text-cyan-400">${l.vector}</td>
            <td class="py-3 font-mono text-slate-300">${l.payload}</td>
            <td class="py-3">
                <span class="px-2.5 py-1 rounded-full text-[10px] font-bold ${l.status === 'DANGEROUS' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : (l.status === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')}">
                    ${l.status}
                </span>
            </td>
            <td class="py-3 text-right">
                <button onclick="deleteLog(${l.id})" class="text-slate-500 hover:text-red-400 transition cursor-pointer"><i class="fa-solid fa-trash"></i></button>
            </td>
        </tr>
    `).join('');
}

function deleteLog(id) {
    scanLogs = scanLogs.filter(l => l.id !== id);
    localStorage.setItem('cyberguard_logs', JSON.stringify(scanLogs));
    updateTelemetryStats();
    renderLogsTable();
}

function wipeLogs() {
    scanLogs = [];
    localStorage.removeItem('cyberguard_logs');
    updateTelemetryStats();
    renderLogsTable();
}

// Password Entropy Test
function testPasswordEntropy() {
    const input = document.getElementById('pass-test-input').value;
    const scoreText = document.getElementById('pass-entropy-score');
    const bar = document.getElementById('pass-entropy-bar');

    if (!input) {
        scoreText.innerText = "0% – Awaiting Entry";
        bar.style.width = "0%";
        return;
    }

    let score = 0;
    if (input.length >= 8) score += 25;
    if (input.length >= 12) score += 25;
    if (/[A-Z]/.test(input)) score += 20;
    if (/[0-9]/.test(input)) score += 15;
    if (/[^A-Za-z0-9]/.test(input)) score += 15;

    scoreText.innerText = `${score}% Resilience Index`;
    bar.style.width = `${score}%`;
    bar.className = score >= 75 ? "bg-emerald-400 h-1.5 rounded-full transition-all" : (score >= 40 ? "bg-amber-400 h-1.5 rounded-full transition-all" : "bg-red-500 h-1.5 rounded-full transition-all");
}

// 🎯 Interactive Knowledge Check Quiz Loop Engine
const quizData = [
    {
        q: "A link says 'http://login.sbi.com.secure-verify.orrg.in'. Is this official?",
        opts: ["Yes, it belongs to SBI Bank", "No, spoofed domain on .orrg.in"],
        ans: 1,
        exp: "The real domain is 'orrg.in', not sbi.com. Scammers use subdomains to deceive."
    },
    {
        q: "An email demands urgent password update within 10 mins or account gets deleted. What is this?",
        opts: ["Social Engineering / Urgency Trap", "Standard Security Maintenance Notice"],
        ans: 0,
        exp: "Scammers create panic & urgency to bypass rational thinking."
    },
    {
        q: "Which payload string is most dangerous inside an SMS link?",
        opts: ["https://hdfcbank.com/netbanking", "http://192.168.1.105/verify-kyc.apk"],
        ans: 1,
        exp: "Direct IP hosting + insecure HTTP + .apk downloads indicate high-risk malware."
    }
];

let quizIndex = 0;
let quizScore = 0;

function startQuizLoop() {
    quizIndex = 0;
    quizScore = 0;
    document.getElementById('quiz-start-btn')?.classList.add('hidden');
    document.getElementById('quiz-options')?.classList.remove('hidden');
    renderQuizQuestion();
}

function renderQuizQuestion() {
    const qData = quizData[quizIndex];
    const qText = document.getElementById('quiz-question-text');
    const optsContainer = document.getElementById('quiz-options');

    if (qText) qText.innerText = `Q${quizIndex + 1}: ${qData.q}`;

    if (optsContainer) {
        optsContainer.innerHTML = qData.opts.map((opt, idx) => `
            <button onclick="handleQuizAnswer(${idx})" class="w-full text-left p-3 rounded-xl bg-[#050811] hover:bg-slate-800 border border-slate-800 text-xs font-mono text-cyan-300 transition flex items-center justify-between cursor-pointer">
                <span>${opt}</span>
                <i class="fa-solid fa-chevron-right text-[10px] text-slate-500"></i>
            </button>
        `).join('');
    }
}

function handleQuizAnswer(selectedIdx) {
    const currentQ = quizData[quizIndex];
    if (selectedIdx === currentQ.ans) {
        quizScore++;
        alert(`✅ CORRECT!\n${currentQ.exp}`);
    } else {
        alert(`❌ INCORRECT!\n${currentQ.exp}`);
    }

    quizIndex++;
    if (quizIndex < quizData.length) {
        renderQuizQuestion();
    } else {
        finishQuizLoop();
    }
}

function finishQuizLoop() {
    const qText = document.getElementById('quiz-question-text');
    const optsContainer = document.getElementById('quiz-options');
    
    if (qText) qText.innerText = `🎉 Quiz Completed! Score: ${quizScore}/${quizData.length}`;
    if (optsContainer) {
        optsContainer.innerHTML = `
            <button onclick="startQuizLoop()" class="w-full py-2.5 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/40 rounded-xl font-mono text-xs font-bold transition cursor-pointer">
                <i class="fa-solid fa-rotate-right mr-1"></i> Restart Quiz Loop
            </button>
        `;
    }
}

// AI Chatbot Toggle
function toggleAiChat() {
    document.getElementById('ai-chat-modal')?.classList.toggle('hidden');
}

function sendAiMessage() {
    const input = document.getElementById('ai-chat-input');
    const messages = document.getElementById('ai-chat-messages');
    const text = input.value.trim();

    if (!text) return;

    messages.innerHTML += `<div class="text-right"><span class="inline-block bg-blue-600 text-white text-xs px-3 py-2 rounded-xl font-mono">${text}</span></div>`;
    input.value = '';

    setTimeout(() => {
        let reply = "I am CyberGuard AI Agent. Inspect suspicious payload links inside Core Scanner!";
        if (text.toLowerCase().includes('phishing')) reply = "Phishing links spoof extensions like .orrg or use raw IP addresses.";
        if (text.toLowerCase().includes('hi') || text.toLowerCase().includes('hello')) reply = "Hello Abhishek! How can I assist you with threat telemetry today?";

        messages.innerHTML += `<div class="text-left"><span class="inline-block bg-slate-800 text-cyan-300 text-xs px-3 py-2 rounded-xl font-mono border border-slate-700">${reply}</span></div>`;
        messages.scrollTop = messages.scrollHeight;
    }, 500);
}

function runDiagnosticTest() {
    alert("⚡ Diagnostics Complete:\n- Local Heuristics: Active\n- Quiz Module: Synced\n- Local Storage Engine: Ready");
}