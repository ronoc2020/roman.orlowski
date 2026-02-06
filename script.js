// Detect mobile device
const isMobile = () => window.innerWidth <= 768;
const isSmallPhone = () => window.innerWidth <= 480;

// Particles.js Configuration - Optimized for mobile
const particleConfig = isMobile() ? {
  particles: {
    number: {
      value: 30,
      density: {
        enable: true,
        value_area: 1000
      }
    },
    color: {
      value: ['#ffff00', '#ff8800', '#dd00ff']
    },
    shape: {
      type: 'circle',
      stroke: {
        width: 0,
        color: '#000000'
      }
    },
    opacity: {
      value: 0.3,
      random: false,
      anim: {
        enable: false
      }
    },
    size: {
      value: 2,
      random: true,
      anim: {
        enable: false
      }
    },
    line_linked: {
      enable: true,
      distance: 100,
      color: '#ffff00',
      opacity: 0.2,
      width: 1
    },
    move: {
      enable: true,
      speed: 1,
      direction: 'none',
      random: false,
      straight: false,
      out_mode: 'out',
      bounce: false
    }
  },
  interactivity: {
    detect_on: 'canvas',
    events: {
      onhover: {
        enable: false,
        mode: 'grab'
      },
      onclick: {
        enable: false,
        mode: 'push'
      },
      resize: true
    }
  },
  retina_detect: true
} : {
  particles: {
    number: {
      value: 60,
      density: {
        enable: true,
        value_area: 800
      }
    },
    color: {
      value: ['#ffff00', '#ff8800', '#dd00ff']
    },
    shape: {
      type: 'circle',
      stroke: {
        width: 0,
        color: '#000000'
      }
    },
    opacity: {
      value: 0.5,
      random: false,
      anim: {
        enable: false
      }
    },
    size: {
      value: 3,
      random: true,
      anim: {
        enable: false
      }
    },
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
      out_mode: 'out',
      bounce: false
    }
  },
  interactivity: {
    detect_on: 'canvas',
    events: {
      onhover: {
        enable: true,
        mode: 'grab'
      },
      onclick: {
        enable: true,
        mode: 'push'
      },
      resize: true
    },
    modes: {
      grab: {
        distance: 140,
        line_linked: {
          opacity: 1
        }
      },
      push: {
        particles_nb: 4
      }
    }
  },
  retina_detect: true
};

particlesJS('particles-js', particleConfig);

// Intro Sequence - Shorter on mobile
document.addEventListener('DOMContentLoaded', function() {
  const introSequence = document.getElementById('intro-sequence');
  const introDelay = isMobile() ? 3000 : 5000;
  
  setTimeout(() => {
    introSequence.style.display = 'none';
  }, introDelay);

  // Pip-Boy Inventory System
  const pipBoyTrigger = document.querySelector('.pip-boy-trigger');
  const pipBoyInventory = document.querySelector('.pip-boy-inventory');
  const inventoryTabs = document.querySelectorAll('.inventory-tab');
  const inventoryContents = document.querySelectorAll('.inventory-content');

  if (pipBoyTrigger) {
    pipBoyTrigger.addEventListener('click', function(e) {
      e.stopPropagation();
      pipBoyInventory.classList.toggle('active');
    });

    // Close inventory when clicking outside
    document.addEventListener('click', function(e) {
      if (!pipBoyTrigger.contains(e.target) && !pipBoyInventory.contains(e.target)) {
        pipBoyInventory.classList.remove('active');
      }
    });

    // Close on escape key
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        pipBoyInventory.classList.remove('active');
      }
    });
  }

  // Inventory Tab Switching
  inventoryTabs.forEach(tab => {
    tab.addEventListener('click', function() {
      inventoryTabs.forEach(t => t.classList.remove('active'));
      inventoryContents.forEach(c => c.classList.remove('active'));
      
      this.classList.add('active');
      const tabName = this.getAttribute('data-tab');
      document.getElementById(tabName).classList.add('active');
    });
  });

  // Intersection Observer for sections
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

  // Navigation
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
      targetSection.style.display = 'block';
      setTimeout(() => {
        targetSection.classList.add('visible');
      }, 10);
      
      // Mobile: scroll with less delay
      const scrollDelay = isMobile() ? 100 : 300;
      setTimeout(() => {
        targetSection.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }, scrollDelay);

      pipBoyInventory.classList.remove('active');
    });
  });

  // Dynamic gradient based on mouse movement (Desktop only)
  const gradient = document.querySelector('.cyber-gradient');
  if (!isMobile()) {
    document.addEventListener('mousemove', (e) => {
      const x = e.clientX / window.innerWidth;
      const y = e.clientY / window.innerHeight;
      gradient.style.background = 
        `linear-gradient(${135 + x * 45}deg, rgba(255, 255, 0, 0.05) 0%, transparent 50%),
         linear-gradient(${-135 + y * 45}deg, rgba(221, 0, 255, 0.05) 0%, transparent 50%)`;
    });

    // Parallax effect for floating elements (Desktop only)
    document.addEventListener('mousemove', (e) => {
      const floatingElements = document.querySelectorAll('.floating-element');
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

  // Enhanced Terminal Commands
  const commands = {
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
      execute: () => 'Roman Orłowski - Cybersecurity Expert | ROCyber Solutions'
    },
    skills: {
      execute: () => `Core Skills:
  • Cloud Security (Azure, AWS, GCP)
  • Threat Analysis & Detection (MITRE ATT&CK, SIEM)
  • Network Security & Zero Trust Architecture
  • Compliance (ISO 27001, GDPR, NIST, NIS2, SOX, DORA)
  • Ethical Hacking (CEH, Penetration Testing)
  • Privacy Protection & Data Security
  • Incident Response & Crisis Management
  • Kubernetes & Container Orchestration`
    },
    nmap: {
      execute: () => `Starting Nmap 7.92 scan...
Scanning target 192.168.1.1...
Discovered open port 80/tcp http
Discovered open port 443/tcp https
Discovered open port 22/tcp ssh
Nmap scan report complete.
Security Assessment: Implement firewall rules and close unnecessary ports.`
    },
    msfconsole: {
      execute: () => `Starting Metasploit Framework console...
       =[ metasploit v6.2.0                  ]
+ -- --=[ 2200 exploits - 1171 auxiliary   ]
+ -- --=[ 400 post modules - 596 payloads  ]

msf6 > use exploit/multi/http/example
msf6 exploit(multi/http/example) > 
Remember: Use ethically for testing only. Always obtain authorization.`
    },
    searchsploit: {
      execute: () => `Searching Exploit-DB...
Results:
  [1] Windows - Remote Code Execution (CVE-2021-xxxxx)
  [2] Linux - Privilege Escalation (CVE-2021-xxxxx)
  [3] Apache - Directory Traversal (CVE-2020-xxxxx)
Report vulnerabilities responsibly through coordinated disclosure.`
    },
    ceh_phases: {
      execute: () => `CEH Ethical Hacking Phases:
  1. Reconnaissance - Information gathering
  2. Scanning - Port scanning and enumeration
  3. Gaining Access - Exploiting vulnerabilities
  4. Maintaining Access - Persistence mechanisms
  5. Covering Tracks - Log cleaning and evasion
Focus on defense and ethical use. Always obtain written authorization.`
    },
    privacy_tip: {
      execute: () => `Privacy Protection Tip:
Use encryption (e.g., VPNs, HTTPS) for all communications.
Enable MFA (Multi-Factor Authentication) on all accounts.
Comply with GDPR for privacy-by-design.
Minimize data collection and implement data retention policies.
Use privacy-respecting tools: Signal, ProtonMail, Tor Browser.`
    },
    disclosure: {
      execute: () => `Responsible Disclosure Best Practices:
  1. Report vulnerabilities to vendors first
  2. Allow reasonable time for patches (90 days)
  3. Avoid public disclosure before fixes
  4. Coordinate with security teams
  5. Follow CVE assignment process
Align with CEH ethics and protect users.`
    },
    analyze_log: {
      execute: () => `Analyzing security logs...
[2024-02-05 14:32:15] Failed login attempt from 192.168.1.100
[2024-02-05 14:33:22] Successful authentication for user: admin
[2024-02-05 14:35:01] Suspicious file access detected
[2024-02-05 14:36:45] Network anomaly: Unusual outbound traffic
Analysis complete. Recommend immediate investigation of anomalies.`
    },
    decrypt_hash: {
      execute: () => `Hash Decryption Tool
Enter hash: 5d41402abc4b2a76b9719d911017c592
Hash Type: MD5
Status: Decrypted
Result: hello
Warning: MD5 is cryptographically broken. Use SHA-256 or better.`
    },
    check_vuln: {
      execute: () => `Checking Vulnerability Database...
Scanning for known CVEs...
CVE-2024-1234: Critical - Remote Code Execution
CVE-2024-5678: High - SQL Injection
CVE-2024-9012: Medium - Cross-Site Scripting
Total Vulnerabilities Found: 3
Recommendation: Apply security patches immediately.`
    },
    owasp_top10: {
      execute: () => `OWASP Top 10 2021:
  1. Broken Access Control
  2. Cryptographic Failures
  3. Injection
  4. Insecure Design
  5. Security Misconfiguration
  6. Vulnerable and Outdated Components
  7. Authentication Failures
  8. Software and Data Integrity Failures
  9. Logging and Monitoring Failures
  10. Server-Side Request Forgery (SSRF)`
    },
    azure_security: {
      execute: () => `Azure Security Best Practices:
  • Enable Azure Defender for comprehensive threat protection
  • Implement Azure Policy for compliance enforcement
  • Use Azure Key Vault for secrets management
  • Enable MFA and Conditional Access
  • Monitor with Azure Sentinel for threat detection
  • Implement network segmentation with NSGs
  • Regular security assessments and penetration testing`
    },
    incident_response: {
      execute: () => `Incident Response Procedures:
  1. PREPARATION: Establish IR team and tools
  2. DETECTION & ANALYSIS: Identify and assess incident
  3. CONTAINMENT: Stop the attack, prevent spread
  4. ERADICATION: Remove attacker access and malware
  5. RECOVERY: Restore systems to normal operations
  6. POST-INCIDENT: Conduct lessons learned review
Timeline: Follow 24-48 hour response protocol`
    },
    threat_hunt: {
      execute: () => `Threat Hunting Techniques:
  • Analyze network traffic patterns (Wireshark, Zeek)
  • Review endpoint logs (Sysmon, Windows Event Viewer)
  • Hunt for suspicious processes and registry changes
  • Identify lateral movement indicators
  • Search for C2 communication patterns
  • Analyze user behavior anomalies
  • Use MITRE ATT&CK framework for TTP mapping`
    },
    malware_analysis: {
      execute: () => `Malware Analysis Workflow:
  1. STATIC ANALYSIS: File properties, strings, imports
  2. DYNAMIC ANALYSIS: Sandbox execution, behavior monitoring
  3. NETWORK ANALYSIS: Traffic capture and protocol analysis
  4. CODE ANALYSIS: Reverse engineering and disassembly
  5. REPORTING: Document findings and IOCs
Tools: IDA Pro, Ghidra, Wireshark, Cuckoo Sandbox`
    },
    forensics: {
      execute: () => `Digital Forensics Guide:
  • Preserve evidence chain of custody
  • Image drives using forensic tools (FTK, EnCase)
  • Analyze file systems (NTFS, ext4, APFS)
  • Recover deleted files and unallocated space
  • Timeline analysis of file system events
  • Memory forensics for RAM analysis
  • Report findings with expert testimony`
    },
    compliance_check: {
      execute: () => `Compliance Framework Overview:
  • ISO 27001: Information Security Management
  • GDPR: Data Protection and Privacy
  • NIST: Cybersecurity Framework
  • PCI-DSS: Payment Card Industry Data Security
  • HIPAA: Healthcare data protection
  • SOX: Financial reporting security
  • DORA: Digital Operational Resilience`
    },
    clear: {
      execute: () => {
        const terminalOutput = document.getElementById('terminal-output');
        terminalOutput.innerHTML = '<div class="terminal-line">Terminal cleared.</div>';
        return '';
      }
    }
  };

  // Terminal Input Handler
  const terminalCommand = document.getElementById('terminal-command');
  const terminalOutput = document.getElementById('terminal-output');
  
  if (terminalCommand) {
    terminalCommand.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        const command = terminalCommand.value.trim().toLowerCase();
        terminalCommand.value = '';
        
        if (!command) return;
        
        // Display command
        const commandLine = document.createElement('div');
        commandLine.className = 'terminal-line';
        commandLine.innerHTML = `<span class="terminal-prompt">$</span> ${command}`;
        terminalOutput.appendChild(commandLine);
        
        // Execute command
        let result;
        if (commands[command]) {
          result = commands[command].execute();
        } else {
          result = `Command not found: ${command}\nType 'help' for available commands`;
        }
        
        // Display result
        if (result) {
          const resultElement = document.createElement('div');
          resultElement.className = 'terminal-line';
          resultElement.style.whiteSpace = 'pre-wrap';
          resultElement.textContent = result;
          terminalOutput.appendChild(resultElement);
        }
        
        // Scroll to bottom
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
      }
    });
  }

  // Music Player
  const audioPlayer = document.getElementById('audio-player');
  const playBtn = document.getElementById('play-btn');
  const pauseBtn = document.getElementById('pause-btn');
  const nextBtn = document.getElementById('next-btn');
  const closeBtn = document.getElementById('close-btn');

  if (playBtn && audioPlayer) {
    playBtn.addEventListener('click', () => {
      audioPlayer.play();
      playBtn.style.display = 'none';
      pauseBtn.style.display = 'inline-block';
    });

    pauseBtn.addEventListener('click', () => {
      audioPlayer.pause();
      pauseBtn.style.display = 'none';
      playBtn.style.display = 'inline-block';
    });

    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        audioPlayer.pause();
        audioPlayer.currentTime = 0;
        playBtn.style.display = 'inline-block';
        pauseBtn.style.display = 'none';
      });
    }
  }

  // Enhanced Quiz Functionality
  const quizOptions = document.querySelectorAll('.quiz-option');
  let quizScore = 0;
  let quizTotal = 0;

  quizOptions.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.quiz-question');
      const feedback = question.querySelector('.quiz-feedback');
      const isCorrect = this.dataset.correct === 'true';
      
      // Prevent multiple answers per question
      if (question.classList.contains('answered')) {
        return;
      }
      
      question.classList.add('answered');
      quizTotal++;
      
      // Remove previous selections
      question.querySelectorAll('.quiz-option').forEach(opt => {
        opt.style.background = 'rgba(20, 20, 30, 0.5)';
        opt.style.borderColor = 'rgba(0, 247, 255, 0.1)';
        opt.style.cursor = 'default';
      });
      
      // Highlight selected option
      if (isCorrect) {
        this.style.background = 'rgba(85, 255, 85, 0.2)';
        this.style.borderColor = 'var(--low)';
        feedback.textContent = '✓ Correct! Great job!';
        feedback.className = 'quiz-feedback correct';
        quizScore++;
      } else {
        this.style.background = 'rgba(255, 85, 85, 0.2)';
        this.style.borderColor = 'var(--critical)';
        feedback.textContent = '✗ Incorrect. Try again!';
        feedback.className = 'quiz-feedback incorrect';
      }
      
      // Display score if all questions answered
      if (quizTotal === quizOptions.length / 4) {
        const scorePercentage = Math.round((quizScore / (quizTotal)) * 100);
        const scoreMessage = document.createElement('div');
        scoreMessage.className = 'terminal-line';
        scoreMessage.style.marginTop = '1rem';
        scoreMessage.style.padding = '1rem';
        scoreMessage.style.background = 'rgba(0, 255, 0, 0.1)';
        scoreMessage.style.border = '1px solid #00ff00';
        scoreMessage.textContent = `Quiz Complete! Score: ${quizScore}/${quizTotal} (${scorePercentage}%)`;
        question.parentElement.appendChild(scoreMessage);
      }
    });
  });

  // Smooth scroll for anchor links
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

  // Add typing effect to header
  const headerTitle = document.querySelector('.header h1');
  if (headerTitle) {
    const letters = headerTitle.querySelectorAll('.letter');
    letters.forEach((letter, index) => {
      letter.style.animationDelay = `${index * 0.05}s`;
    });
  }

  // Handle window resize for responsive adjustments
  window.addEventListener('resize', () => {
    // Adjust layout on resize if needed
    if (isMobile() && pipBoyInventory.classList.contains('active')) {
      // Ensure inventory is properly positioned on resize
      pipBoyInventory.style.width = '100%';
    }
  });

  // Prevent zoom on double-tap (mobile)
  let lastTouchEnd = 0;
  document.addEventListener('touchend', function(event) {
    const now = Date.now();
    if (now - lastTouchEnd <= 300) {
      event.preventDefault();
    }
    lastTouchEnd = now;
  }, false);
});
