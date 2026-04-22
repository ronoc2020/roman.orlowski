// Detect mobile device
const isMobile = () => window.innerWidth <= 768;
const isSmallPhone = () => window.innerWidth <= 480;

// Particles.js Configuration
const particleConfig = isMobile() ? {
  particles: { number: { value: 30, density: { enable: true, value_area: 1000 } }, color: { value: ['#ffff00', '#ff8800', '#dd00ff'] }, shape: { type: 'circle' }, opacity: { value: 0.3 }, size: { value: 2, random: true }, line_linked: { enable: true, distance: 100, color: '#ffff00', opacity: 0.2, width: 1 }, move: { enable: true, speed: 1, direction: 'none', out_mode: 'out' } },
  interactivity: { detect_on: 'canvas', events: { onhover: { enable: false }, onclick: { enable: false }, resize: true } },
  retina_detect: true
} : {
  particles: { number: { value: 60, density: { enable: true, value_area: 800 } }, color: { value: ['#ffff00', '#ff8800', '#dd00ff'] }, shape: { type: 'circle' }, opacity: { value: 0.5 }, size: { value: 3, random: true }, line_linked: { enable: true, distance: 150, color: '#ffff00', opacity: 0.4, width: 1 }, move: { enable: true, speed: 2, direction: 'none', out_mode: 'out' } },
  interactivity: { detect_on: 'canvas', events: { onhover: { enable: true, mode: 'grab' }, onclick: { enable: true, mode: 'push' }, resize: true }, modes: { grab: { distance: 140, line_linked: { opacity: 1 } }, push: { particles_nb: 4 } } },
  retina_detect: true
};

// Initialize particles
if (typeof particlesJS !== 'undefined') {
  particlesJS('particles-js', particleConfig);
}

// Terminal Commands
const commands = {
  help: { execute: () => `Available commands:\n  help, whoami, skills, nmap, msfconsole, searchsploit, ceh_phases, privacy_tip, disclosure, analyze_log, decrypt_hash, check_vuln, owasp_top10, azure_security, incident_response, threat_hunt, malware_analysis, forensics, compliance_check, clear` },
  whoami: { execute: () => 'Roman Orłowski - Cybersecurity Expert | ROCyber Solutions' },
  skills: { execute: () => `Core Skills:\n  • Cloud Security (Azure, AWS, GCP)\n  • Threat Analysis & Detection (MITRE ATT&CK, SIEM)\n  • Network Security & Zero Trust Architecture\n  • Compliance (ISO 27001, GDPR, NIST, NIS2, SOX, DORA)\n  • Ethical Hacking (CEH, Penetration Testing)\n  • Privacy Protection & Data Security\n  • Incident Response & Crisis Management` },
  nmap: { execute: () => `Starting Nmap 7.92 scan...\nScanning target 192.168.1.1...\nDiscovered open port 80/tcp http\nDiscovered open port 443/tcp https\nDiscovered open port 22/tcp ssh\nNmap scan report complete.` },
  msfconsole: { execute: () => `Starting Metasploit Framework console...\n       =[ metasploit v6.2.0                  ]\n+ -- --=[ 2200 exploits - 1171 auxiliary   ]\nmsf6 > use exploit/multi/http/example` },
  searchsploit: { execute: () => `Searching Exploit-DB...\nResults:\n  [1] Windows - Remote Code Execution (CVE-2021-xxxxx)\n  [2] Linux - Privilege Escalation (CVE-2021-xxxxx)\n  [3] Apache - Directory Traversal (CVE-2020-xxxxx)` },
  ceh_phases: { execute: () => `CEH Ethical Hacking Phases:\n  1. Reconnaissance - Information gathering\n  2. Scanning - Port scanning and enumeration\n  3. Gaining Access - Exploiting vulnerabilities\n  4. Maintaining Access - Persistence mechanisms\n  5. Covering Tracks - Log cleaning and evasion` },
  privacy_tip: { execute: () => `Privacy Protection Tip:\nUse encryption (VPNs, HTTPS) for all communications.\nEnable MFA on all accounts.\nComply with GDPR for privacy-by-design.\nUse privacy-respecting tools: Signal, ProtonMail, Tor Browser.` },
  disclosure: { execute: () => `Responsible Disclosure Best Practices:\n  1. Report vulnerabilities to vendors first\n  2. Allow reasonable time for patches (90 days)\n  3. Avoid public disclosure before fixes\n  4. Coordinate with security teams\n  5. Follow CVE assignment process` },
  analyze_log: { execute: () => `Analyzing security logs...\n[2024-02-05 14:32:15] Failed login attempt from 192.168.1.100\n[2024-02-05 14:33:22] Successful authentication for user: admin\n[2024-02-05 14:35:01] Suspicious file access detected\nAnalysis complete.` },
  decrypt_hash: { execute: () => `Hash Decryption Tool\nEnter hash: 5d41402abc4b2a76b9719d911017c592\nHash Type: MD5\nStatus: Decrypted\nResult: hello\nWarning: MD5 is broken. Use SHA-256.` },
  check_vuln: { execute: () => `Checking Vulnerability Database...\nCVE-2024-1234: Critical - Remote Code Execution\nCVE-2024-5678: High - SQL Injection\nCVE-2024-9012: Medium - Cross-Site Scripting\nRecommendation: Apply security patches immediately.` },
  owasp_top10: { execute: () => `OWASP Top 10 2021:\n  1. Broken Access Control\n  2. Cryptographic Failures\n  3. Injection\n  4. Insecure Design\n  5. Security Misconfiguration\n  6. Vulnerable Components\n  7. Authentication Failures\n  8. Software Integrity Failures\n  9. Logging Failures\n  10. SSRF` },
  azure_security: { execute: () => `Azure Security Best Practices:\n  • Enable Azure Defender\n  • Implement Azure Policy\n  • Use Azure Key Vault\n  • Enable MFA and Conditional Access\n  • Monitor with Azure Sentinel` },
  incident_response: { execute: () => `Incident Response Procedures:\n  1. PREPARATION: Establish IR team\n  2. DETECTION & ANALYSIS: Identify incident\n  3. CONTAINMENT: Stop the attack\n  4. ERADICATION: Remove attacker access\n  5. RECOVERY: Restore systems\n  6. POST-INCIDENT: Lessons learned` },
  threat_hunt: { execute: () => `Threat Hunting Techniques:\n  • Analyze network traffic patterns\n  • Review endpoint logs\n  • Identify lateral movement indicators\n  • Search for C2 communication patterns\n  • Use MITRE ATT&CK framework` },
  malware_analysis: { execute: () => `Malware Analysis Workflow:\n  1. STATIC ANALYSIS: File properties, strings\n  2. DYNAMIC ANALYSIS: Sandbox execution\n  3. NETWORK ANALYSIS: Traffic capture\n  4. CODE ANALYSIS: Reverse engineering\n  5. REPORTING: Document IOCs` },
  forensics: { execute: () => `Digital Forensics Guide:\n  • Preserve chain of custody\n  • Image drives using forensic tools\n  • Analyze file systems\n  • Recover deleted files\n  • Memory forensics for RAM analysis` },
  compliance_check: { execute: () => `Compliance Framework Overview:\n  • ISO 27001: Information Security Management\n  • GDPR: Data Protection and Privacy\n  • NIST: Cybersecurity Framework\n  • PCI-DSS: Payment Security\n  • SOX: Financial reporting\n  • DORA: Digital Operational Resilience` },
  clear: { execute: () => { const output = document.getElementById('terminal-output'); if (output) output.innerHTML = '<div class="terminal-line">Terminal cleared.</div>'; return ''; } }
};

document.addEventListener('DOMContentLoaded', function() {
  // Intro sequence
  const introSequence = document.getElementById('intro-sequence');
  const introDelay = isMobile() ? 3000 : 5000;
  setTimeout(() => { if (introSequence) introSequence.style.display = 'none'; }, introDelay);

  // Pip-Boy Inventory System
  const pipBoyTrigger = document.querySelector('.pip-boy-trigger');
  const pipBoyInventory = document.querySelector('.pip-boy-inventory');
  const inventoryTabs = document.querySelectorAll('.inventory-tab');
  const inventoryContents = document.querySelectorAll('.inventory-content');

  if (pipBoyTrigger && pipBoyInventory) {
    pipBoyTrigger.addEventListener('click', function(e) {
      e.stopPropagation();
      pipBoyInventory.classList.toggle('active');
    });
    document.addEventListener('click', function(e) {
      if (!pipBoyTrigger.contains(e.target) && !pipBoyInventory.contains(e.target)) {
        pipBoyInventory.classList.remove('active');
      }
    });
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') pipBoyInventory.classList.remove('active');
    });
  }

  if (inventoryTabs.length) {
    inventoryTabs.forEach(tab => {
      tab.addEventListener('click', function() {
        inventoryTabs.forEach(t => t.classList.remove('active'));
        inventoryContents.forEach(c => c.classList.remove('active'));
        this.classList.add('active');
        const tabName = this.getAttribute('data-tab');
        const targetContent = document.getElementById(tabName);
        if (targetContent) targetContent.classList.add('active');
      });
    });
  }

  // Navigation
  const navItems = document.querySelectorAll('.nav-item');
  const sections = document.querySelectorAll('.section');

  if (navItems.length && sections.length) {
    navItems.forEach(item => {
      item.addEventListener('click', function() {
        navItems.forEach(nav => nav.classList.remove('active'));
        this.classList.add('active');
        sections.forEach(section => { section.classList.remove('visible'); section.style.display = 'none'; });
        const sectionId = this.getAttribute('data-section');
        const targetSection = document.getElementById(sectionId);
        if (targetSection) {
          targetSection.style.display = 'block';
          setTimeout(() => targetSection.classList.add('visible'), 10);
          const scrollDelay = isMobile() ? 100 : 300;
          setTimeout(() => targetSection.scrollIntoView({ behavior: 'smooth', block: 'start' }), scrollDelay);
        }
        if (pipBoyInventory) pipBoyInventory.classList.remove('active');
      });
    });
  }

  // Dynamic gradient for desktop
  const gradient = document.querySelector('.cyber-gradient');
  if (gradient && !isMobile()) {
    document.addEventListener('mousemove', (e) => {
      const x = e.clientX / window.innerWidth;
      const y = e.clientY / window.innerHeight;
      gradient.style.background = `linear-gradient(${135 + x * 45}deg, rgba(255, 255, 0, 0.05) 0%, transparent 50%), linear-gradient(${-135 + y * 45}deg, rgba(221, 0, 255, 0.05) 0%, transparent 50%)`;
    });
  }

  // Parallax for floating elements (desktop only)
  if (!isMobile()) {
    const floatingElements = document.querySelectorAll('.floating-element');
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

  // Terminal Input Handler
  const terminalCommand = document.getElementById('terminal-command');
  const terminalOutput = document.getElementById('terminal-output');
  
  if (terminalCommand && terminalOutput) {
    terminalCommand.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        const command = terminalCommand.value.trim().toLowerCase();
        terminalCommand.value = '';
        if (!command) return;
        
        const commandLine = document.createElement('div');
        commandLine.className = 'terminal-line';
        commandLine.innerHTML = `<span class="terminal-prompt">$</span> ${command}`;
        terminalOutput.appendChild(commandLine);
        
        let result;
        if (commands[command]) {
          result = commands[command].execute();
        } else {
          result = `Command not found: ${command}\nType 'help' for available commands`;
        }
        
        if (result) {
          const resultElement = document.createElement('div');
          resultElement.className = 'terminal-line';
          resultElement.style.whiteSpace = 'pre-wrap';
          resultElement.textContent = result;
          terminalOutput.appendChild(resultElement);
        }
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
      }
    });
  }

  // Quiz Functionality
  const quizOptions = document.querySelectorAll('.quiz-option');
  let quizScore = 0;
  let quizTotal = 0;
  let totalQuestions = document.querySelectorAll('.quiz-question').length;

  quizOptions.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.quiz-question');
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
        feedback.textContent = '✓ Correct! Great job!';
        feedback.className = 'quiz-feedback correct';
        quizScore++;
      } else {
        this.style.background = 'rgba(255, 85, 85, 0.2)';
        this.style.borderColor = 'var
