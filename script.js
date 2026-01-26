// Particles.js Configuration
particlesJS('particles-js', {
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
});

// Intro Sequence
document.addEventListener('DOMContentLoaded', function() {
  const introSequence = document.getElementById('intro-sequence');
  
  setTimeout(() => {
    introSequence.style.display = 'none';
  }, 5000);

  // Pip-Boy Inventory System
  const pipBoyTrigger = document.querySelector('.pip-boy-trigger');
  const pipBoyInventory = document.querySelector('.pip-boy-inventory');
  const inventoryTabs = document.querySelectorAll('.inventory-tab');
  const inventoryContents = document.querySelectorAll('.inventory-content');

  if (pipBoyTrigger) {
    pipBoyTrigger.addEventListener('click', function() {
      pipBoyInventory.classList.toggle('active');
    });

    // Close inventory when clicking outside
    document.addEventListener('click', function(e) {
      if (!pipBoyTrigger.contains(e.target) && !pipBoyInventory.contains(e.target)) {
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
      
      targetSection.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });

      pipBoyInventory.classList.remove('active');
    });
  });

  // Dynamic gradient based on mouse movement
  const gradient = document.querySelector('.cyber-gradient');
  document.addEventListener('mousemove', (e) => {
    const x = e.clientX / window.innerWidth;
    const y = e.clientY / window.innerHeight;
    gradient.style.background = 
      `linear-gradient(${135 + x * 45}deg, rgba(255, 255, 0, 0.05) 0%, transparent 50%),
       linear-gradient(${-135 + y * 45}deg, rgba(221, 0, 255, 0.05) 0%, transparent 50%)`;
  });

  // Parallax effect for floating elements
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

  // Terminal Commands
  const commands = {
    help: {
      execute: () => `Available commands:
  help          - Show this help message
  whoami        - Display current user
  skills        - List cybersecurity skills
  nmap          - Simulate network scan
  msfconsole    - Launch Metasploit console
  searchsploit  - Search exploit database
  ceh_phases    - Display CEH hacking phases
  privacy_tip   - Get privacy protection tip
  disclosure    - Learn about responsible disclosure
  clear         - Clear terminal output`
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
Discovered open port 80/tcp on target
Discovered open port 443/tcp on target
Discovered open port 22/tcp on target
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
        const command = terminalCommand.value.trim();
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

  // Quiz Functionality
  const quizOptions = document.querySelectorAll('.quiz-option');
  quizOptions.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.quiz-question');
      const feedback = question.querySelector('.quiz-feedback');
      const isCorrect = this.dataset.correct === 'true';
      
      // Remove previous selections
      question.querySelectorAll('.quiz-option').forEach(opt => {
        opt.style.background = 'rgba(20, 20, 30, 0.5)';
        opt.style.borderColor = 'rgba(0, 247, 255, 0.1)';
      });
      
      // Highlight selected option
      if (isCorrect) {
        this.style.background = 'rgba(85, 255, 85, 0.2)';
        this.style.borderColor = 'var(--low)';
        feedback.textContent = '✓ Correct! Great job!';
        feedback.className = 'quiz-feedback correct';
      } else {
        this.style.background = 'rgba(255, 85, 85, 0.2)';
        this.style.borderColor = 'var(--critical)';
        feedback.textContent = '✗ Incorrect. Try again!';
        feedback.className = 'quiz-feedback incorrect';
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
});
