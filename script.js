// Detect mobile device
const isMobile = () => window.innerWidth <= 768;

// Particles.js Configuration
const particleConfig = isMobile() ? {
    particles: {
        number: { value: 35, density: { enable: true, value_area: 1000 } },
        color: { value: ['#ffff00', '#ff8800', '#dd00ff'] },
        shape: { type: 'circle' },
        opacity: { value: 0.4, random: true },
        size: { value: 2, random: true },
        line_linked: { enable: true, distance: 100, color: '#ffff00', opacity: 0.2, width: 1 },
        move: { enable: true, speed: 1, direction: 'none', out_mode: 'out' }
    },
    interactivity: { detect_on: 'canvas', events: { onhover: { enable: false }, onclick: { enable: false }, resize: true } },
    retina_detect: true
} : {
    particles: {
        number: { value: 100, density: { enable: true, value_area: 800 } },
        color: { value: ['#ffff00', '#ff8800', '#dd00ff'] },
        shape: { type: 'circle' },
        opacity: { value: 0.6, random: true },
        size: { value: 3, random: true },
        line_linked: { enable: true, distance: 150, color: '#ffff00', opacity: 0.4, width: 1 },
        move: { enable: true, speed: 2, direction: 'none', out_mode: 'out' }
    },
    interactivity: {
        detect_on: 'canvas',
        events: { onhover: { enable: true, mode: 'grab' }, onclick: { enable: true, mode: 'push' }, resize: true },
        modes: { grab: { distance: 140, line_linked: { opacity: 1 } }, push: { particles_nb: 4 } }
    },
    retina_detect: true
};

// Initialize particles
if (typeof particlesJS !== 'undefined') {
    particlesJS('particles-js', particleConfig);
}

// Pip-Boy Terminal Commands
const pipCommands = {
    help: () => `Available commands:\n  help, whoami, skills, verify, clear, date, status, scan, report`,
    whoami: () => 'ROCyber_Security_System v2.0 | User: Admin',
    skills: () => `Loaded Modules:\n  • Threat Detection (Active)\n  • SIEM Integration (Active)\n  • Zero Trust Enforcement (Active)\n  • Compliance Scanner (Active)`,
    verify: (code) => {
        const storedCode = localStorage.getItem('verificationCode') || 'CYBER-2024-TRUST';
        if (code && code.toUpperCase() === storedCode) {
            return 'ACCESS GRANTED. You are verified. Welcome, trusted candidate.';
        }
        return 'ACCESS DENIED. Invalid verification code.';
    },
    clear: () => { 
        const output = document.getElementById('pipTerminalOutput');
        if (output) output.innerHTML = '<div class="terminal-line">> Terminal cleared.</div>';
        return '';
    },
    date: () => `System Time: ${new Date().toLocaleString()}`,
    status: () => `Security Status: ACTIVE\nThreat Level: LOW\nLast Scan: ${new Date().toLocaleDateString()}`,
    scan: () => `Scanning network...\n0 threats detected.\nSystem secure.`,
    report: () => `Weekly Report:\n  • Incidents: 0\n  • Patches Applied: 3\n  • Compliance: 100%`
};

// Main Terminal Commands (for main terminal)
const mainCommands = {
    help: () => `Available commands:\n  help, whoami, skills, nmap, msfconsole, searchsploit, ceh_phases, privacy_tip, disclosure, analyze_log, decrypt_hash, check_vuln, owasp_top10, azure_security, incident_response, threat_hunt, malware_analysis, forensics, compliance_check, clear`,
    whoami: () => 'Roman Orłowski - Cybersecurity Expert | ROCyber Solutions',
    skills: () => `Core Skills:\n  • Cloud Security (Azure, AWS, GCP)\n  • Threat Analysis & Detection (MITRE ATT&CK, SIEM)\n  • Network Security & Zero Trust Architecture\n  • Compliance (ISO 27001, GDPR, NIST, NIS2, SOX, DORA)\n  • Ethical Hacking (CEH, Penetration Testing)\n  • Incident Response & Crisis Management`,
    nmap: () => `Starting Nmap 7.92 scan...\nScanning target 192.168.1.1...\nDiscovered open port 80/tcp http\nDiscovered open port 443/tcp https\nDiscovered open port 22/tcp ssh\nNmap scan report complete.`,
    msfconsole: () => `Starting Metasploit Framework console...\n       =[ metasploit v6.2.0                  ]\n+ -- --=[ 2200 exploits - 1171 auxiliary   ]\nmsf6 > use exploit/multi/http/example`,
    searchsploit: () => `Searching Exploit-DB...\nResults:\n  [1] Windows - Remote Code Execution (CVE-2021-xxxxx)\n  [2] Linux - Privilege Escalation (CVE-2021-xxxxx)`,
    ceh_phases: () => `CEH Ethical Hacking Phases:\n  1. Reconnaissance\n  2. Scanning\n  3. Gaining Access\n  4. Maintaining Access\n  5. Covering Tracks`,
    privacy_tip: () => `Privacy Protection Tip:\nUse encryption (VPNs, HTTPS).\nEnable MFA on all accounts.\nComply with GDPR.\nUse Signal, ProtonMail, Tor Browser.`,
    disclosure: () => `Responsible Disclosure:\n  1. Report to vendors first\n  2. Allow 90 days for patches\n  3. Coordinate with security teams\n  4. Follow CVE process`,
    analyze_log: () => `Analyzing security logs...\n[${new Date().toLocaleString()}] Failed login attempts: 0\n[Suspicious activity]: None detected\nAnalysis complete. System secure.`,
    decrypt_hash: () => `Hash Decryption Tool\nHash: 5d41402abc4b2a76b9719d911017c592\nType: MD5\nResult: hello\nWarning: MD5 is broken. Use SHA-256.`,
    check_vuln: () => `Checking Vulnerability Database...\nNo critical CVEs found for current stack.\nLast scan: ${new Date().toLocaleDateString()}`,
    owasp_top10: () => `OWASP Top 10 2021:\n  1. Broken Access Control\n  2. Cryptographic Failures\n  3. Injection\n  4. Insecure Design\n  5. Security Misconfiguration`,
    azure_security: () => `Azure Security Best Practices:\n  • Enable Azure Defender\n  • Implement Azure Policy\n  • Use Azure Key Vault\n  • Enable MFA\n  • Monitor with Azure Sentinel`,
    incident_response: () => `Incident Response Procedures:\n  1. PREPARATION\n  2. DETECTION & ANALYSIS\n  3. CONTAINMENT\n  4. ERADICATION\n  5. RECOVERY\n  6. POST-INCIDENT`,
    threat_hunt: () => `Threat Hunting Techniques:\n  • Network traffic analysis\n  • Endpoint log review\n  • Lateral movement detection\n  • C2 communication patterns\n  • MITRE ATT&CK mapping`,
    malware_analysis: () => `Malware Analysis Workflow:\n  1. STATIC ANALYSIS\n  2. DYNAMIC ANALYSIS\n  3. NETWORK ANALYSIS\n  4. CODE ANALYSIS\n  5. REPORTING`,
    forensics: () => `Digital Forensics Guide:\n  • Preserve chain of custody\n  • Image drives\n  • Analyze file systems\n  • Recover deleted files\n  • Memory forensics`,
    compliance_check: () => `Compliance Framework Overview:\n  • ISO 27001\n  • GDPR\n  • NIST CSF\n  • PCI-DSS\n  • SOX\n  • DORA`,
    clear: () => {
        const output = document.getElementById('terminal-output');
        if (output) output.innerHTML = '<div class="terminal-line">Terminal cleared. Type "help" for commands.</div>';
        return '';
    }
};

document.addEventListener('DOMContentLoaded', function() {
    // ============ INTRO SEQUENCE ============
    const introSequence = document.getElementById('intro-sequence');
    const introDelay = isMobile() ? 3000 : 5000;
    setTimeout(() => { if (introSequence) introSequence.style.display = 'none'; }, introDelay);

    // ============ RECRUITMENT PANEL (Hidden - Ctrl+Shift+A) ============
    const recruitmentPanel = document.getElementById('recruitment-panel');
    let ctrlPressed = false, shiftPressed = false, aPressed = false;
    
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Control') ctrlPressed = true;
        if (e.key === 'Shift') shiftPressed = true;
        if (e.key === 'a' || e.key === 'A') aPressed = true;
        
        if (ctrlPressed && shiftPressed && aPressed && recruitmentPanel) {
            e.preventDefault();
            recruitmentPanel.classList.toggle('active');
        }
    });
    
    document.addEventListener('keyup', function(e) {
        if (e.key === 'Control') ctrlPressed = false;
        if (e.key === 'Shift') shiftPressed = false;
        if (e.key === 'a' || e.key === 'A') aPressed = false;
    });
    
    // Close recruitment panel
    const closeRecruitment = document.getElementById('closeRecruitment');
    if (closeRecruitment) {
        closeRecruitment.addEventListener('click', () => {
            if (recruitmentPanel) recruitmentPanel.classList.remove('active');
        });
    }
    
    // Regenerate verification code
    const regenerateCode = document.getElementById('regenerateCode');
    const verificationCodeSpan = document.getElementById('verificationCode');
    if (regenerateCode && verificationCodeSpan) {
        regenerateCode.addEventListener('click', () => {
            const newCode = 'CYBER-' + Math.random().toString(36).substring(2, 10).toUpperCase();
            verificationCodeSpan.textContent = newCode;
            localStorage.setItem('verificationCode', newCode);
        });
        // Load stored code or set default
        const storedCode = localStorage.getItem('verificationCode');
        if (storedCode) verificationCodeSpan.textContent = storedCode;
    }

    // ============ PIP-BOY INVENTORY ============
    const pipBoyTrigger = document.getElementById('pipBoyTrigger');
    const pipBoyInventory = document.getElementById('pipBoyInventory');
    const pipBoyClose = document.getElementById('pipBoyClose');
    const inventoryTabs = document.querySelectorAll('.inventory-tab');
    const inventoryContents = document.querySelectorAll('.inventory-content');

    if (pipBoyTrigger && pipBoyInventory) {
        pipBoyTrigger.addEventListener('click', function(e) {
            e.stopPropagation();
            pipBoyInventory.classList.toggle('active');
        });
        
        if (pipBoyClose) {
            pipBoyClose.addEventListener('click', function() {
                pipBoyInventory.classList.remove('active');
            });
        }
        
        document.addEventListener('click', function(e) {
            if (!pipBoyTrigger.contains(e.target) && !pipBoyInventory.contains(e.target)) {
                pipBoyInventory.classList.remove('active');
            }
        });
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') pipBoyInventory.classList.remove('active');
        });
    }

    // Inventory tabs
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

    // ============ MUSIC PLAYER ============
    const audioPlayer = document.getElementById('audio-player');
    const playBtn = document.getElementById('play-btn');
    const pauseBtn = document.getElementById('pause-btn');
    const stopBtn = document.getElementById('stop-btn');
    
    if (audioPlayer && playBtn && pauseBtn && stopBtn) {
        // Try to load audio, fallback to silent if fails
        audioPlayer.volume = 0.5;
        
        playBtn.addEventListener('click', () => {
            audioPlayer.play().catch(e => console.log('Audio play failed:', e));
            playBtn.style.display = 'none';
            pauseBtn.style.display = 'inline-flex';
        });
        
        pauseBtn.addEventListener('click', () => {
            audioPlayer.pause();
            pauseBtn.style.display = 'none';
            playBtn.style.display = 'inline-flex';
        });
        
        stopBtn.addEventListener('click', () => {
            audioPlayer.pause();
            audioPlayer.currentTime = 0;
            pauseBtn.style.display = 'none';
            playBtn.style.display = 'inline-flex';
        });
    }

    // ============ PIP-BOY TERMINAL ============
    const pipTerminalCommand = document.getElementById('pipTerminalCommand');
    const pipTerminalOutput = document.getElementById('pipTerminalOutput');
    
    if (pipTerminalCommand && pipTerminalOutput) {
        pipTerminalCommand.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const fullCommand = this.value.trim();
                this.value = '';
                if (!fullCommand) return;
                
                // Add command to output
                const commandLine = document.createElement('div');
                commandLine.className = 'terminal-line';
                commandLine.innerHTML = `<span class="terminal-prompt">$</span> ${fullCommand}`;
                pipTerminalOutput.appendChild(commandLine);
                
                // Parse command and argument
                const parts = fullCommand.toLowerCase().split(' ');
                const command = parts[0];
                const arg = parts.slice(1).join(' ');
                
                let result;
                if (pipCommands[command]) {
                    result = pipCommands[command](arg);
                } else {
                    result = `Command not found: ${command}\nType 'help' for available commands`;
                }
                
                if (result) {
                    const resultElement = document.createElement('div');
                    resultElement.className = 'terminal-line';
                    resultElement.style.whiteSpace = 'pre-wrap';
                    resultElement.textContent = result;
                    pipTerminalOutput.appendChild(resultElement);
                }
                
                pipTerminalOutput.scrollTop = pipTerminalOutput.scrollHeight;
            }
        });
    }

    // ============ MAIN NAVIGATION ============
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.section');

    if (navItems.length && sections.length) {
        // Hide all sections except about
        sections.forEach(section => {
            if (section.id !== 'about') {
                section.style.display = 'none';
                section.classList.remove('visible');
            }
        });

        navItems.forEach(item => {
            item.addEventListener('click', function() {
                // Update active nav
                navItems.forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
                
                // Hide all sections
                sections.forEach(section => {
                    section.style.display = 'none';
                    section.classList.remove('visible');
                });
                
                // Show selected section
                const sectionId = this.getAttribute('data-section');
                const targetSection = document.getElementById(sectionId);
                if (targetSection) {
                    targetSection.style.display = 'block';
                    setTimeout(() => targetSection.classList.add('visible'), 10);
                    
                    const scrollDelay = isMobile() ? 100 : 300;
                    setTimeout(() => {
                        targetSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }, scrollDelay);
                }
                
                // Close pip-boy
                if (pipBoyInventory) pipBoyInventory.classList.remove('active');
            });
        });
    }

    // ============ MAIN TERMINAL ============
    const terminalCommand = document.getElementById('terminal-command');
    const terminalOutput = document.getElementById('terminal-output');
    
    if (terminalCommand && terminalOutput) {
        terminalCommand.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const command = this.value.trim().toLowerCase();
                this.value = '';
                if (!command) return;
                
                const commandLine = document.createElement('div');
                commandLine.className = 'terminal-line';
                commandLine.innerHTML = `<span class="terminal-prompt">$</span> ${command}`;
                terminalOutput.appendChild(commandLine);
                
                let result;
                if (mainCommands[command]) {
                    result = mainCommands[command]();
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

    // ============ QUIZ FUNCTIONALITY ============
    const quizOptions = document.querySelectorAll('.quiz-option');
    let quizScore = 0;
    let quizTotal = 0;
    const totalQuestions = document.querySelectorAll('.quiz-question').length;

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
                this.style.borderColor = '#55ff55';
                feedback.textContent = '✓ Correct! Great job!';
                feedback.className = 'quiz-feedback correct';
                quizScore++;
            } else {
                this.style.background = 'rgba(255, 85, 85, 0.2)';
                this.style.borderColor = '#ff5555';
                feedback.textContent = '✗ Incorrect. The correct answer is highlighted.';
                feedback.className = 'quiz-feedback incorrect';
                // Show correct answer
                question.querySelectorAll('.quiz-option').forEach(opt => {
                    if (opt.dataset.correct === 'true') {
                        opt.style.background = 'rgba(85, 255, 85, 0.15)';
                        opt.style.borderColor = '#55ff55';
                    }
                });
            }
            
            if (quizTotal === totalQuestions) {
                const scorePercentage = Math.round((quizScore / totalQuestions) * 100);
                const quizContainer = document.querySelector('.quiz-container');
                const existingScore = quizContainer.querySelector('.final-score');
                if (!existingScore) {
                    const scoreMessage = document.createElement('div');
                    scoreMessage.className = 'final-score';
                    scoreMessage.style.marginTop = '1rem';
                    scoreMessage.style.padding = '1rem';
                    scoreMessage.style.background = 'rgba(0, 255, 0, 0.1)';
                    scoreMessage.style.border = '1px solid #00ff00';
                    scoreMessage.style.textAlign = 'center';
                    scoreMessage.style.borderRadius = '8px';
                    scoreMessage.innerHTML = `<i class="fas fa-chart-line"></i> Quiz Complete! Score: ${quizScore}/${totalQuestions} (${scorePercentage}%)`;
                    quizContainer.appendChild(scoreMessage);
                }
            }
        });
    });

    // ============ DYNAMIC GRADIENT (DESKTOP) ============
    const gradient = document.querySelector('.cyber-gradient');
    if (gradient && !isMobile()) {
        document.addEventListener('mousemove', (e) => {
            const x = e.clientX / window.innerWidth;
            const y = e.clientY / window.innerHeight;
            gradient.style.background = `linear-gradient(${135 + x * 45}deg, rgba(255, 255, 0, 0.05) 0%, transparent 50%), linear-gradient(${-135 + y * 45}deg, rgba(221, 0, 255, 0.05) 0%, transparent 50%)`;
        });
    }

    // ============ PARALLAX EFFECT (DESKTOP) ============
    if (!isMobile()) {
        const floatingElements = document.querySelectorAll('.floating-element');
        document.addEventListener('mousemove', (e) => {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;
            floatingElements.forEach((element, index) => {
                const speed = (index + 1) * 0.03;
                const x = (mouseX - 0.5) * 100 * speed;
                const y = (mouseY - 0.5) * 100 * speed;
                element.style.transform = `translate(${x}px, ${y}px)`;
            });
        });
    }

    // ============ SMOOTH SCROLL FOR ANCHORS ============
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    // ============ RESIZE HANDLER ============
    window.addEventListener('resize', () => {
        if (isMobile() && pipBoyInventory && pipBoyInventory.classList.contains('active')) {
            pipBoyInventory.style.width = '100%';
        }
    });

    // ============ PREVENT ZOOM ON DOUBLE TAP (MOBILE) ============
    let lastTouchEnd = 0;
    document.addEventListener('touchend', function(event) {
        const now = Date.now();
        if (now - lastTouchEnd <= 300) {
            event.preventDefault();
        }
        lastTouchEnd = now;
    }, false);
    
    // ============ CONSOLE WELCOME MESSAGE ============
    console.log('%c🔐 ROCyber Security System Online', 'color: #00ff00; font-size: 16px; font-weight: bold;');
    console.log('%cTip: Press Ctrl+Shift+A for recruitment panel', 'color: #ffff00; font-size: 12px;');
});
