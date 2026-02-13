// ============================================
// PIP-BOY SELF ASSESSMENT – 15 PYTAŃ REKRUTACYJNYCH
// SZYFROWANIE AES, WERYFIKACJA PRZEZ SHA256
// PEŁNA WERSJA Z QUIZEM, TERMINALEM, MUZYKĄ
// ============================================

// 🔐 Tutaj wpisz hash SHA256 swojego tajnego hasła.
// Przykład dla hasła "Vault111Operator!" 
const SECRET_HASH = "c7e8c9f8a9b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0";

// ========== BAZA PYTAŃ SELF ASSESSMENT ==========
const selfAssessmentQuestions = [
  {
    question: "1. Jakie środowisko pracy preferujesz?",
    options: [
      "A) W pełni zdalne, bez konieczności dojazdów – maksymalna elastyczność",
      "B) Hybrydowe (2-3 dni w biurze) – balans między kontaktem a wygodą",
      "C) Stacjonarne – lubię pracę zespołową i bezpośredni kontakt",
      "D) Elastyczne – zależy od projektu, potrafię dostosować się do firmy"
    ]
  },
  {
    question: "2. Jak reagujesz na restrykcyjne procedury bezpieczeństwa?",
    options: [
      "A) To podstawa – sam je wdrażam i wymagam od innych",
      "B) Akceptuję, ale czasem spowalniają pracę – szukam złotego środka",
      "C) Wolę swobodę i zaufanie, ale stosuję się do polityk",
      "D) Negocjuję wyjątki, jeśli procedura jest nielogiczna"
    ]
  },
  {
    question: "3. Co jest dla Ciebie najważniejsze w kulturze firmy?",
    options: [
      "A) Transparentność, feedback, otwartość na błędy",
      "B) Rozwój, szkolenia, budżet na certyfikaty",
      "C) Work-life balance i szacunek do czasu prywatnego",
      "D) Silne przywództwo i jasno określone cele"
    ]
  },
  {
    question: "4. Jak oceniasz swoją odporność na nudę przy rutynowych zadaniach?",
    options: [
      "A) Automatyzuję wszystko, żeby uniknąć nudy",
      "B) Rutyna mi nie przeszkadza – traktuję ją jako medytację",
      "C) Potrzebuję różnorodności, szybko się nudzę",
      "D) Przeplatanie zadań – robię przerwy na research"
    ]
  },
  {
    question: "5. Wolisz pracę samodzielną czy zespołową?",
    options: [
      "A) Samodzielną – skupiam się lepiej",
      "B) Zespołową – wymiana wiedzy motywuje",
      "C) 50/50 – zależy od zadania",
      "D) Lubię prowadzić małe zespoły (tech lead)"
    ]
  },
  {
    question: "6. Jak podchodzisz do presji czasu i incydentów?",
    options: [
      "A) Zachowuję zimną krew, działam według playbooka",
      "B) Stres mobilizuje mnie do szybkich decyzji",
      "C) Potrzebuję chwili na analizę, potem działam",
      "D) Współpracuję z zespołem – nie biorę wszystkiego na siebie"
    ]
  },
  {
    question: "7. Czy akceptujesz dyżury (on-call)?",
    options: [
      "A) Tak, to część pracy w operacjach",
      "B) Tylko za dodatkowym wynagrodzeniem",
      "C) Wolę unikać, ale rozumiem konieczność",
      "D) Nie – szukam pracy bez dyżurów"
    ]
  },
  {
    question: "8. Jak widzisz swój rozwój w ciągu 3 lat?",
    options: [
      "A) Architekt rozwiązań chmurowych / Security Architect",
      "B) Specjalista od pentestów / red team",
      "C) Management / CISO",
      "D) Głęboka specjalizacja w wybranej dziedzinie (np. Kubernetes)"
    ]
  },
  {
    question: "9. Co sądzisz o ciągłym doskonaleniu (CI/CD w procesach)?",
    options: [
      "A) Niezbędne – automatyzacja to podstawa DevSecOps",
      "B) Ważne, ale nie kosztem stabilności",
      "C) Wdrożyłem to w poprzednich firmach",
      "D) Dopiero się tego uczę – chłonę wiedzę"
    ]
  },
  {
    question: "10. Jakie masz podejście do błędów i incydentów?",
    options: [
      "A) Blameless post-mortem – szukamy przyczyn, nie winnych",
      "B) Kultura sprawiedliwości – uczymy się na błędach",
      "C) Ważne aby szybko przywrócić działanie, potem analiza",
      "D) Spisywanie lessons learned to klucz"
    ]
  },
  {
    question: "11. Czy angażujesz się w życie firmy poza obowiązkami?",
    options: [
      "A) Tak, lubię integracje i eventy",
      "B) Czasami, jeśli temat mnie zainteresuje",
      "C) Raczej nie – praca to praca",
      "D) Organizuję wewnętrzne szkolenia"
    ]
  },
  {
    question: "12. Jak reagujesz na krytykę swojego kodu / rozwiązań?",
    options: [
      "A) Z wdzięcznością – code review to nauka",
      "B) Bronię swoich decyzji, ale jestem otwarty",
      "C) Zniechęcam się, jeśli krytyka jest ostra",
      "D) Proszę o konkretne przykłady i sugestie"
    ]
  },
  {
    question: "13. Czy lubisz uczyć innych (mentoring)?",
    options: [
      "A) Tak, to część mojej roli",
      "B) Chętnie, jeśli junior jest zaangażowany",
      "C) Wolę skupić się na własnych zadaniach",
      "D) Prowadziłem już onboarding nowych osób"
    ]
  },
  {
    question: "14. Jakie narzędzia do komunikacji preferujesz?",
    options: [
      "A) Slack/Teams – szybkie wiadomości",
      "B) E-mail – formalnie i na piśmie",
      "C) Bezpośrednie rozmowy / stand-upy",
      "D) Wszystkie, dostosowuję się do zespołu"
    ]
  },
  {
    question: "15. Co najbardziej motywuje Cię do pracy?",
    options: [
      "A) Ciekawe wyzwania techniczne",
      "B) Wpływ na bezpieczeństwo firmy",
      "C) Atmosfera i ludzie",
      "D) Wynagrodzenie i benefity"
    ]
  }
];

// ========== FUNKCJE KRYPTOGRAFICZNE ==========
function encryptResult(data, password) {
  return CryptoJS.AES.encrypt(JSON.stringify(data), password).toString();
}

function decryptResult(ciphertext, password) {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, password);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(decrypted);
  } catch (e) {
    return null;
  }
}

// ========== OBLICZANIE WYNIKU SELF ASSESSMENT ==========
function calculateFitScore(answers) {
  let total = 0;
  for (let i = 0; i < 15; i++) {
    if (answers[i] !== undefined) total += parseInt(answers[i]);
  }
  const max = 15 * 3;
  const percent = Math.round((total / max) * 100);
  
  let recommendation = "";
  if (percent >= 80) recommendation = "Excellent fit – strong candidate for SOC/Cloud team";
  else if (percent >= 60) recommendation = "Good fit – meets requirements, minor gaps";
  else if (percent >= 40) recommendation = "Average fit – additional training recommended";
  else recommendation = "Low fit – consider different role or seniority level";
  
  return {
    score: percent,
    recommendation: recommendation,
    breakdown: "Based on 15 recruiter questions about work culture, environment and soft skills",
    raw: answers,
    timestamp: new Date().toISOString()
  };
}

// ========== RENDEROWANIE PYTAŃ SELF ASSESSMENT ==========
function renderSelfAssessment() {
  const container = document.getElementById('self-assessment-questions');
  if (!container) return;
  
  let html = '';
  selfAssessmentQuestions.forEach((q, idx) => {
    html += `<div class="quiz-question" style="background: rgba(0,30,0,0.7); border-color: #0f0; margin-bottom: 1rem; padding: 1rem; border-radius: 4px;">`;
    html += `<h4 style="color: #cfc; display: flex; gap: 0.5rem; margin-bottom: 0.8rem; font-size: 1rem;">`;
    html += `<i class="fas fa-user-tie" style="color: #0f0;"></i> ${q.question}</h4>`;
    html += `<div class="quiz-options" style="display: flex; flex-direction: column; gap: 0.5rem;">`;
    
    q.options.forEach((opt, optIdx) => {
      const savedAnswers = JSON.parse(localStorage.getItem('self_assessment_answers') || '{}');
      const isSelected = savedAnswers[idx] == optIdx;
      
      html += `<div class="quiz-option" data-question="${idx}" data-option="${optIdx}" style="border: 1px solid #0f0; background: ${isSelected ? 'rgba(0,255,0,0.25)' : 'rgba(0,40,0,0.6)'}; color: #dfd; padding: 0.7rem; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 0.5rem; transition: all 0.2s;">`;
      html += `<i class="fas fa-circle-chevron-right" style="color: #0f0;"></i> ${opt}`;
      html += `</div>`;
    });
    html += `</div></div>`;
  });
  container.innerHTML = html;

  // Zdarzenia dla opcji – zapis do localStorage
  document.querySelectorAll('#self-assessment-questions .quiz-option').forEach(opt => {
    opt.addEventListener('click', function(e) {
      const qIdx = this.dataset.question;
      const optIdx = this.dataset.option;
      let answers = JSON.parse(localStorage.getItem('self_assessment_answers') || '{}');
      answers[qIdx] = optIdx;
      localStorage.setItem('self_assessment_answers', JSON.stringify(answers));
      
      // Podświetlenie wybranej opcji
      this.parentElement.querySelectorAll('.quiz-option').forEach(o => {
        o.style.background = 'rgba(0,40,0,0.6)';
        o.style.borderColor = '#0f0';
      });
      this.style.background = 'rgba(0,255,0,0.25)';
      this.style.borderColor = '#ff0';
    });
  });
}

// ========== OBSŁUGA KOMEND TERMINALA SELF ASSESSMENT ==========
function handleSelfAssessmentCommand(cmd) {
  const resultDiv = document.getElementById('self-assessment-result');
  const cipherPre = document.getElementById('result-cipher');
  const cmdLower = cmd.toLowerCase().trim();

  if (cmdLower === 'help') {
    return `Available commands:
  help                     – this message
  results                  – generate encrypted result (requires all answers)
  decrypt <password>       – decrypt and show result (only operator)
  status                   – show how many questions answered
  clear                    – clear all answers and reset
  export                   – export encrypted result as base64
  load <base64>            – load previously exported result`;
  }

  if (cmdLower === 'status') {
    const answers = JSON.parse(localStorage.getItem('self_assessment_answers') || '{}');
    const answered = Object.keys(answers).length;
    let statusMsg = `[✓] Answered: ${answered}/15 questions.`;
    
    if (answered < 15) {
      const missing = [];
      for (let i = 0; i < 15; i++) {
        if (!answers[i]) missing.push(i+1);
      }
      statusMsg += `\n[!] Missing questions: ${missing.join(', ')}`;
    }
    return statusMsg;
  }

  if (cmdLower === 'results') {
    const answers = JSON.parse(localStorage.getItem('self_assessment_answers') || '{}');
    if (Object.keys(answers).length < 15) {
      return `[!] Not all questions answered (${Object.keys(answers).length}/15). Complete assessment first.`;
    }
    const scoreData = calculateFitScore(answers);
    const encrypted = encryptResult(scoreData, "temp");
    cipherPre.dataset.encrypted = encrypted;
    cipherPre.textContent = '';
    resultDiv.style.display = 'block';
    return `[✓] Assessment complete. Encrypted result ready.\nType: decrypt <your_password> to view.\nType: export to get base64 code.`;
  }

  if (cmdLower === 'export') {
    const encrypted = document.getElementById('result-cipher')?.dataset.encrypted;
    if (!encrypted) {
      return `[!] No encrypted result found. Type 'results' first.`;
    }
    return `[✓] Export your encrypted result:\n${encrypted}`;
  }

  if (cmdLower.startsWith('load ')) {
    const encryptedData = cmd.substring(5);
    if (!encryptedData) {
      return `[!] No data provided. Usage: load <base64_encrypted_data>`;
    }
    const cipherPre = document.getElementById('result-cipher');
    cipherPre.dataset.encrypted = encryptedData;
    cipherPre.textContent = '';
    document.getElementById('self-assessment-result').style.display = 'block';
    return `[✓] Encrypted result loaded. Type 'decrypt <password>' to view.`;
  }

  if (cmdLower.startsWith('decrypt ')) {
    const password = cmd.substring(8);
    const hash = CryptoJS.SHA256(password).toString();
    if (hash !== SECRET_HASH) {
      return `[!] Access denied. Wrong password.`;
    }
    const encrypted = document.getElementById('result-cipher')?.dataset.encrypted;
    if (!encrypted) {
      return `[!] No encrypted result found. Type 'results' first.`;
    }
    const decrypted = decryptResult(encrypted, password);
    if (!decrypted) {
      return `[!] Decryption failed. Invalid data or wrong password.`;
    }
    return `[✓] DECRYPTED SCORE: ${decrypted.score}%
[✓] Recommendation: ${decrypted.recommendation}
[✓] Breakdown: ${decrypted.breakdown}
[✓] Timestamp: ${decrypted.timestamp}
[✓] Raw answers: ${JSON.stringify(decrypted.raw)}`;
  }

  if (cmdLower === 'clear') {
    localStorage.removeItem('self_assessment_answers');
    const resultDiv = document.getElementById('self-assessment-result');
    if (resultDiv) {
      resultDiv.style.display = 'none';
      const cipherPre = document.getElementById('result-cipher');
      if (cipherPre) cipherPre.dataset.encrypted = '';
    }
    renderSelfAssessment();
    return '[✓] Assessment reset. All answers cleared.';
  }

  return `Unknown command: ${cmd}. Type 'help'.`;
}

// ========== ORYGINALNE KOMENDY TERMINALA ==========
const terminalCommands = {
  help: {
    execute: () => `Available commands:
  help              - Show this help message
  whoami            - Display current user
  skills            - List cybersecurity skills
  nmap              - Simulate network scan
  msfconsole        - Launch Metasploit console
  searchsploit      - Search exploit database
  ceh_phases        - Display CEH hacking phases
  privacy_tip       - Get privacy protection tip
  disclosure        - Learn about responsible disclosure
  analyze_log       - Analyze security log
  decrypt_hash      - Hash decryption tool
  check_vuln        - Check vulnerability database
  owasp_top10       - Display OWASP Top 10
  azure_security    - Azure security best practices
  incident_response - Incident response procedures
  threat_hunt       - Threat hunting techniques
  malware_analysis  - Malware analysis workflow
  forensics         - Digital forensics guide
  compliance_check  - Compliance framework overview
  clear             - Clear terminal output`
  },
  whoami: {
    execute: () => 'Roman Orłowski - Cybersecurity Expert | ROCyber Solutions | CISSP, CISM, CISA, GSLC, GSTRT, GCPM, AZ-500'
  },
  skills: {
    execute: () => `Core Skills:
  • Cloud Security (Azure, AWS, GCP, Kubernetes)
  • Threat Analysis & Detection (MITRE ATT&CK, SIEM)
  • Network Security & Zero Trust Architecture
  • Compliance (ISO 27001, GDPR, NIST, NIS2, SOX, DORA)
  • Ethical Hacking (CEH, Penetration Testing)
  • Privacy Protection & Data Security
  • Incident Response & Crisis Management
  • DevSecOps & CI/CD Security
  • IAM & PAM (Identity and Access Management)
  • OSINT & Threat Intelligence`
  },
  nmap: {
    execute: () => `Starting Nmap 7.94 (https://nmap.org) ...
Scanning target 192.168.1.0/24...
Discovered open port 22/tcp on 192.168.1.1 (ssh)
Discovered open port 80/tcp on 192.168.1.1 (http)
Discovered open port 443/tcp on 192.168.1.1 (https)
Discovered open port 3389/tcp on 192.168.1.10 (ms-wbt-server)
Discovered open port 445/tcp on 192.168.1.15 (microsoft-ds)
Nmap scan report complete.
Security Assessment: Implement firewall rules, close unnecessary ports, patch known vulnerabilities.`
  },
  msfconsole: {
    execute: () => `Starting Metasploit Framework console...
       =[ metasploit v6.3.4-dev                  ]
+ -- --=[ 2348 exploits - 1205 auxiliary - 412 post ]
+ -- --=[ 596 payloads - 45 encoders - 8 nops       ]
+ -- --=[ 9 evasion - 476 payloads                ]

msf6 > use exploit/multi/http/struts2_rest_xstream
msf6 exploit(multi/http/struts2_rest_xstream) > set RHOSTS target.company.com
msf6 exploit(multi/http/struts2_rest_xstream) > set RPORT 8080
msf6 exploit(multi/http/struts2_rest_xstream) > check

[!] Remember: Use ethically for authorized testing only.`
  },
  searchsploit: {
    execute: () => `Searching Exploit-DB Database...
Results:
  [1] Apache Log4j2 2.14.1 - JNDI Injection Remote Code Execution (CVE-2021-44228)
  [2] Microsoft Exchange Server 2019 - Remote Code Execution (ProxyShell)
  [3] Linux Kernel 5.8 - Privilege Escalation (CVE-2021-3490)
  [4] WordPress 5.7 - Unauthenticated RCE (CVE-2021-29447)
  [5] sudo 1.8.31 - Privilege Escalation (CVE-2021-3156)
  
Report vulnerabilities responsibly through coordinated disclosure.`
  },
  ceh_phases: {
    execute: () => `CEH Ethical Hacking Phases:
  1. Reconnaissance - Passive/Active information gathering
  2. Scanning & Enumeration - Port scanning, vulnerability detection
  3. Gaining Access - Exploiting vulnerabilities
  4. Maintaining Access - Backdoors, persistence mechanisms
  5. Covering Tracks - Log cleaning, steganography, evasion
  
Focus on defense and ethical use. Always obtain written authorization.`
  },
  privacy_tip: {
    execute: () => `Privacy Protection Tips:
  • Use end-to-end encryption (Signal, ProtonMail, Wire)
  • Enable MFA/2FA on all accounts (prefer hardware tokens)
  • Use password manager (Bitwarden, KeePass, 1Password)
  • Regular privacy audits - review app permissions
  • Use VPN for public Wi-Fi (WireGuard, OpenVPN)
  • GDPR compliance: data minimization, purpose limitation
  • Privacy-focused browsers: Firefox, Brave, Tor Browser`
  },
  disclosure: {
    execute: () => `Responsible Disclosure Best Practices:
  1. Report vulnerabilities PRIVATELY to vendors first
  2. Provide detailed technical information and PoC
  3. Allow reasonable time for patches (typically 90 days)
  4. NEVER publicly disclose before fixes are available
  5. Coordinate public release with vendor
  6. Follow CVE assignment process (cve.mitre.org)
  7. Consider bug bounty programs for monetary rewards`
  },
  analyze_log: {
    execute: () => `Analyzing security logs from /var/log/auth.log...
[2024-02-13 08:12:15] Failed password for root from 45.155.205.233 port 54322 ssh2
[2024-02-13 08:12:17] Failed password for root from 45.155.205.233 port 54324 ssh2
[2024-02-13 08:12:19] Failed password for root from 45.155.205.233 port 54326 ssh2
[2024-02-13 08:12:22] Invalid user admin from 45.155.205.233 port 54328
[2024-02-13 08:15:33] Accepted password for roman from 192.168.1.100 port 49872 ssh2
[2024-02-13 09:45:22] sudo: roman : TTY=pts/1 ; PWD=/home/roman ; USER=root ; COMMAND=/bin/cat /etc/shadow

Analysis: Brute force attack detected from 45.155.205.233 (China). Blocked by fail2ban.`
  },
  decrypt_hash: {
    execute: () => `Hash Decryption Tool
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Type: MD5
Dictionary attack: 'password'
Result: password
Status: Cracked (weak password)

Hash: 7c6a180b36896a0a8c02787eeafb0e4c
Type: MD5
Dictionary attack: 'admin123'
Result: admin123
Status: Cracked (weak password)

Warning: MD5 and SHA1 are cryptographically broken. Use bcrypt, Argon2, or PBKDF2.`
  },
  check_vuln: {
    execute: () => `Checking vulnerability database (CVE)...
Target: Apache 2.4.49

CVE-2021-41773: Path traversal and RCE - CRITICAL
  CVSS: 7.5 (High)
  Affected: Apache 2.4.49 only
  Fix: Upgrade to 2.4.51 or later

CVE-2021-42013: Path traversal and RCE - CRITICAL  
  CVSS: 7.5 (High)
  Affected: Apache 2.4.49, 2.4.50
  Fix: Upgrade to 2.4.51 or later

Recommendation: IMMEDIATE upgrade required - critical vulnerabilities detected.`
  },
  owasp_top10: {
    execute: () => `OWASP Top 10 2021:
  A01:2021 - Broken Access Control
  A02:2021 - Cryptographic Failures
  A03:2021 - Injection
  A04:2021 - Insecure Design
  A05:2021 - Security Misconfiguration
  A06:2021 - Vulnerable and Outdated Components
  A07:2021 - Identification and Authentication Failures
  A08:2021 - Software and Data Integrity Failures
  A09:2021 - Security Logging and Monitoring Failures
  A10:2021 - Server-Side Request Forgery (SSRF)
  
More info: https://owasp.org/Top10/`
  },
  azure_security: {
    execute: () => `Azure Security Best Practices:
  • Enable Microsoft Defender for Cloud (formerly Azure Security Center)
  • Implement Azure Policy for compliance enforcement (NIST, ISO 27001, CIS)
  • Use Azure Key Vault for secrets, keys, and certificates management
  • Enable MFA and Conditional Access for all users
  • Deploy Azure Sentinel as cloud-native SIEM/SOAR
  • Implement network segmentation with NSGs and Azure Firewall
  • Use Azure Bastion for secure RDP/SSH access (no public IPs)
  • Enable Azure DDoS Protection for critical workloads
  • Regular security assessments with Azure Secure Score
  • Encrypt data at rest with Azure Storage Service Encryption`
  },
  incident_response: {
    execute: () => `Incident Response Procedures (NIST SP 800-61):
  
  1. PREPARATION:
     - Establish IR policy and procedures
     - Deploy necessary tools (EDR, SIEM, forensics)
     - Train team members, conduct tabletop exercises
  
  2. DETECTION & ANALYSIS:
     - Identify incident via alerts, reports, or monitoring
     - Determine scope, severity, and impact
     - Preserve evidence (chain of custody)
  
  3. CONTAINMENT, ERADICATION & RECOVERY:
     - Short-term: isolate affected systems
     - Long-term: apply patches, remove malware
     - Restore from clean backups
  
  4. POST-INCIDENT ACTIVITY:
     - Lessons learned report
     - Update policies and procedures
     - Legal and regulatory reporting (GDPR, DORA, etc.)`
  },
  threat_hunt: {
    execute: () => `Threat Hunting Techniques:
  
  • Hypothesis-driven hunting (based on threat intelligence)
  • IOC hunting (known malicious hashes, domains, IPs)
  • TTP hunting (MITRE ATT&CK framework)
  • Anomaly detection (baselining, statistical analysis)
  
  Data Sources:
  • Network traffic (NetFlow, Zeek, PCAP)
  • Endpoint logs (Sysmon, Windows Event Logs, auditd)
  • Process creation and command-line arguments
  • Registry and file system changes
  • DNS queries (potential C2 communication)
  
  Tools: Velociraptor, OSQuery, GRR, Kape, Hayabusa`
  },
  malware_analysis: {
    execute: () => `Malware Analysis Workflow:
  
  STATIC ANALYSIS:
  • File fingerprinting (hash, entropy, signatures)
  • String extraction and analysis
  • PE header analysis (imports, exports, sections)
  • Detect packers/protectors (UPX, Themida, VMProtect)
  
  DYNAMIC ANALYSIS:
  • Sandbox execution (Cuckoo, CAPE, Joe Sandbox)
  • Process monitor (Procmon, Process Hacker)
  • Network traffic capture (Wireshark, FakeNet-NG)
  • Registry and file system monitoring
  
  REVERSE ENGINEERING:
  • Disassembly (IDA Pro, Ghidra, x64dbg)
  • Debugging and breakpoints
  • Decompilation (Hex-Rays, Ghidra)`
  },
  forensics: {
    execute: () => `Digital Forensics (DFIR):
  
  ACQUISITION:
  • Create forensic images (FTK Imager, dd, Guymager)
  • Write blockers for hardware preservation
  • Memory acquisition (LiME, FTK Imager, WinPmem)
  
  ANALYSIS:
  • Timeline analysis (Plaso/log2timeline)
  • File carving (Foremost, Scalpel, Photorec)
  • Registry analysis (RegRipper, Zimmerman tools)
  • Browser forensics (Chrome, Firefox, Edge)
  • Email forensics (PST/OST, EDB files)
  
  REPORTING:
  • Chain of custody documentation
  • Executive summary and technical findings
  • Expert testimony preparation`
  },
  compliance_check: {
    execute: () => `Compliance Framework Overview:
  
  ISO 27001:2022 - Information Security Management
    • 93 controls in 4 domains
    • Annex A: Organizational, People, Physical, Technological
  
  NIST CSF - Cybersecurity Framework
    • Identify, Protect, Detect, Respond, Recover
  
  GDPR - Data Protection
    • Articles 5, 32, 33, 35 (security, breach notification, DPIA)
  
  DORA - Digital Operational Resilience Act
    • ICT risk management, testing, incident reporting
  
  PCI DSS v4.0 - Payment Card Industry
    • 12 requirements for cardholder data protection
  
  NIS2 - Network and Information Security
    • Critical entities, supply chain security, incident reporting`
  },
  clear: {
    execute: () => {
      const terminalOutput = document.getElementById('terminal-output');
      if (terminalOutput) {
        terminalOutput.innerHTML = '<div class="terminal-line"><span class="terminal-prompt">$</span> Terminal cleared.</div>';
      }
      return '';
    }
  }
};

// ========== INIT PARTICLES.JS ==========
function initParticles() {
  if (typeof particlesJS !== 'undefined') {
    particlesJS('particles-js', {
      particles: {
        number: { value: 40, density: { enable: true, value_area: 800 } },
        color: { value: ['#ffff00', '#ff8800', '#dd00ff'] },
        shape: { type: 'circle' },
        opacity: { value: 0.5, random: false },
        size: { value: 3, random: true },
        line_linked: { 
          enable: true, 
          distance: 150, 
          color: '#ffff00', 
          opacity: 0.4, 
          width: 1 
        },
        move: { 
          enable: true, 
          speed: 2, 
          direction: 'none', 
          random: false, 
          straight: false, 
          out_mode: 'out' 
        }
      },
      interactivity: {
        detect_on: 'canvas',
        events: { 
          onhover: { enable: true, mode: 'grab' }, 
          onclick: { enable: true, mode: 'push' }, 
          resize: true 
        },
        modes: { 
          grab: { distance: 140, line_linked: { opacity: 1 } }, 
          push: { particles_nb: 4 } 
        }
      },
      retina_detect: true
    });
  }
}

// ========== INIT PIP-BOY ==========
function initPipBoy() {
  const trigger = document.querySelector('.pip-boy-trigger');
  const inventory = document.querySelector('.pip-boy-inventory');
  
  if (trigger && inventory) {
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      inventory.classList.toggle('active');
    });
    
    document.addEventListener('click', (e) => {
      if (!trigger.contains(e.target) && !inventory.contains(e.target)) {
        inventory.classList.remove('active');
      }
    });
  }

  // Inventory tabs
  document.querySelectorAll('.inventory-tab').forEach(tab => {
    tab.addEventListener('click', function() {
      document.querySelectorAll('.inventory-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.inventory-content').forEach(c => c.classList.remove('active'));
      this.classList.add('active');
      const tabId = this.dataset.tab;
      const content = document.getElementById(tabId);
      if (content) content.classList.add('active');
    });
  });
}

// ========== INIT TERMINAL ==========
function initTerminal() {
  const terminalOutput = document.getElementById('terminal-output');
  const terminalCommand = document.getElementById('terminal-command');
  
  if (terminalCommand && terminalOutput) {
    terminalCommand.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        const cmd = this.value.trim().toLowerCase();
        this.value = '';
        
        const commandLine = document.createElement('div');
        commandLine.className = 'terminal-line';
        commandLine.innerHTML = `<span class="terminal-prompt">$</span> ${cmd}`;
        terminalOutput.appendChild(commandLine);
        
        if (cmd === 'clear') {
          terminalOutput.innerHTML = '<div class="terminal-line"><span class="terminal-prompt">$</span> Terminal cleared.</div>';
        } else if (terminalCommands[cmd]) {
          const result = terminalCommands[cmd].execute();
          if (result) {
            const resultLines = result.split('\n');
            resultLines.forEach(line => {
              const resultElement = document.createElement('div');
              resultElement.className = 'terminal-line';
              resultElement.style.whiteSpace = 'pre-wrap';
              resultElement.style.color = '#0f0';
              resultElement.textContent = line;
              terminalOutput.appendChild(resultElement);
            });
          }
        } else {
          const errorElement = document.createElement('div');
          errorElement.className = 'terminal-line';
          errorElement.style.color = '#ff5555';
          errorElement.textContent = `Command not found: ${cmd}. Type 'help' for available commands.`;
          terminalOutput.appendChild(errorElement);
        }
        
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
      }
    });
  }
}

// ========== INIT SELF ASSESSMENT TERMINAL ==========
function initSelfAssessmentTerminal() {
  const cmdInput = document.getElementById('self-assessment-cmd');
  const terminalOutput = document.getElementById('terminal-output');
  
  if (cmdInput && terminalOutput) {
    cmdInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        const cmd = this.value.trim();
        this.value = '';
        const result = handleSelfAssessmentCommand(cmd);
        
        if (result) {
          const line = document.createElement('div');
          line.className = 'terminal-line';
          line.innerHTML = `<span class="terminal-prompt"><i class="fas fa-chevron-right" style="color: #0f0;"></i></span> ${cmd}`;
          terminalOutput.appendChild(line);
          
          const resultLines = result.split('\n');
          resultLines.forEach(lineText => {
            const resLine = document.createElement('div');
            resLine.className = 'terminal-line';
            resLine.style.whiteSpace = 'pre-wrap';
            resLine.style.color = '#afa';
            resLine.textContent = lineText;
            terminalOutput.appendChild(resLine);
          });
          
          terminalOutput.scrollTop = terminalOutput.scrollHeight;
        }
      }
    });
  }
}

// ========== INIT QUIZ ==========
function initQuiz() {
  const quizOptions = document.querySelectorAll('.quiz-section .quiz-option, .quiz-container .quiz-option');
  let quizScore = 0;
  let quizTotal = 0;
  
  quizOptions.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.quiz-question');
      if (!question) return;
      
      const feedback = question.querySelector('.quiz-feedback');
      const isCorrect = this.dataset.correct === 'true';
      
      if (question.classList.contains('answered')) return;
      question.classList.add('answered');
      quizTotal++;
      
      question.querySelectorAll('.quiz-option').forEach(opt => {
        opt.style.background = 'rgba(20, 20, 30, 0.5)';
        opt.style.borderColor = 'rgba(0, 247, 255, 0.1)';
        opt.style.cursor = 'default';
      });
      
      if (isCorrect) {
        this.style.background = 'rgba(85, 255, 85, 0.2)';
        this.style.borderColor = 'var(--low)';
        if (feedback) {
          feedback.textContent = '✓ Correct! Great job!';
          feedback.className = 'quiz-feedback correct';
        }
        quizScore++;
      } else {
        this.style.background = 'rgba(255, 85, 85, 0.2)';
        this.style.borderColor = 'var(--critical)';
        if (feedback) {
          feedback.textContent = '✗ Incorrect. Try again!';
          feedback.className = 'quiz-feedback incorrect';
        }
      }
      
      if (quizTotal === document.querySelectorAll('.quiz-question').length) {
        const scorePercentage = Math.round((quizScore / quizTotal) * 100);
        setTimeout(() => {
          alert(`Quiz Complete! Score: ${quizScore}/${quizTotal} (${scorePercentage}%)`);
        }, 100);
      }
    });
  });
}

// ========== INIT NAVIGATION ==========
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const sections = document.querySelectorAll('.section');
  
  navItems.forEach(item => {
    item.addEventListener('click', function() {
      navItems.forEach(nav => nav.classList.remove('active'));
      this.classList.add('active');
      
      sections.forEach(section => {
        section.classList.remove('visible');
        section.style.display = 'none';
      });
      
      const sectionId = this.getAttribute('data-section');
      const targetSection = document.getElementById(sectionId);
      if (targetSection) {
        targetSection.style.display = 'block';
        setTimeout(() => {
          targetSection.classList.add('visible');
        }, 10);
        
        targetSection.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
      
      const pipBoyInventory = document.querySelector('.pip-boy-inventory');
      if (pipBoyInventory) pipBoyInventory.classList.remove('active');
    });
  });
  
  // Show first section by default
  const firstSection = document.querySelector('.section');
  if (firstSection) {
    firstSection.style.display = 'block';
    firstSection.classList.add('visible');
  }
}

// ========== INTRO SEQUENCE ==========
function initIntro() {
  setTimeout(() => {
    const intro = document.getElementById('intro-sequence');
    if (intro) intro.style.display = 'none';
  }, 5000);
}

// ========== CYBER GRADIENT ==========
function initCyberGradient() {
  const gradient = document.querySelector('.cyber-gradient');
  if (gradient) {
    document.addEventListener('mousemove', (e) => {
      const x = e.clientX / window.innerWidth;
      const y = e.clientY / window.innerHeight;
      gradient.style.background = 
        `linear-gradient(${135 + x * 45}deg, rgba(255, 255, 0, 0.05) 0%, transparent 50%),
         linear-gradient(${-135 + y * 45}deg, rgba(221, 0, 255, 0.05) 0%, transparent 50%)`;
    });
  }
}

// ========== FLOATING ELEMENTS ==========
function initFloatingElements() {
  const floatingElements = document.querySelectorAll('.floating-element');
  if (floatingElements.length) {
    document.addEventListener('mousemove', (e) => {
      const mouseX = e.clientX / window.innerWidth;
      const mouseY = e.clientY / window.innerHeight;
      
      floatingElements.forEach((element, index) => {
        const speed = (index + 1) * 0.05;
        const x = (mouseX - 0.5) * 100 * speed;
        const y = (mouseY - 0.5) * 100 * speed;
        element.style.transform = `translate(${x}px, ${y}px)`;
      });
    });
  }
}

// ========== TYPING EFFECT ==========
function initTypingEffect() {
  const headerTitle = document.querySelector('.header h1');
  if (headerTitle) {
    const letters = headerTitle.querySelectorAll('.letter');
    letters.forEach((letter, index) => {
      letter.style.animationDelay = `${index * 0.05}s`;
    });
  }
}

// ========== SMOOTH SCROLL ==========
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
}

// ========== INTERSECTION OBSERVER ==========
function initIntersectionObserver() {
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, observerOptions);

  document.querySelectorAll('.section').forEach(section => {
    observer.observe(section);
  });
}

// ========== AUDIO PLAYER ==========
function initAudioPlayer() {
  const audioPlayer = document.getElementById('audio-player');
  const playBtn = document.getElementById('play-btn');
  const pauseBtn = document.getElementById('pause-btn');
  const closeBtn = document.getElementById('close-btn');

  if (playBtn && audioPlayer) {
    playBtn.addEventListener('click', () => {
      audioPlayer.play().catch(e => console.log('Audio play failed:', e));
      playBtn.style.display = 'none';
      if (pauseBtn) pauseBtn.style.display = 'inline-block';
    });

    if (pauseBtn) {
      pauseBtn.addEventListener('click', () => {
        audioPlayer.pause();
        pauseBtn.style.display = 'none';
        playBtn.style.display = 'inline-block';
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        audioPlayer.pause();
        audioPlayer.currentTime = 0;
        playBtn.style.display = 'inline-block';
        if (pauseBtn) pauseBtn.style.display = 'none';
      });
    }
  }
}

// ========== DOCUMENT READY ==========
document.addEventListener('DOMContentLoaded', function() {
  // Render self assessment questions
  renderSelfAssessment();
  
  // Initialize all components
  initParticles();
  initPipBoy();
  initTerminal();
  initSelfAssessmentTerminal();
  initQuiz();
  initNavigation();
  initIntro();
  initCyberGradient();
  initFloatingElements();
  initTypingEffect();
  initSmoothScroll();
  initIntersectionObserver();
  initAudioPlayer();
  
  console.log('Pip-Boy OS initialized. Welcome, operator.');
});

// ========== WINDOW RESIZE HANDLER ==========
window.addEventListener('resize', function() {
  // Adjust UI on resize if needed
  const pipBoyInventory = document.querySelector('.pip-boy-inventory');
  if (pipBoyInventory && window.innerWidth <= 768) {
    pipBoyInventory.style.width = '100%';
  }
});

// ========== PREVENT ZOOM ON MOBILE ==========
let lastTouchEnd = 0;
document.addEventListener('touchend', function(event) {
  const now = Date.now();
  if (now - lastTouchEnd <= 300) {
    event.preventDefault();
  }
  lastTouchEnd = now;
}, false);
