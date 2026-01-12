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
      value: ['#00f7ff', '#00ffaa', '#ff00f7']
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
      color: '#00f7ff',
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
      // Remove active class from all nav items
      navItems.forEach(nav => nav.classList.remove('active'));
      
      // Add active class to clicked item
      this.classList.add('active');
      
      // Hide all sections
      sections.forEach(section => {
        section.classList.remove('visible');
        section.style.display = 'none';
      });
      
      // Show selected section
      const sectionId = this.getAttribute('data-section');
      const targetSection = document.getElementById(sectionId);
      targetSection.style.display = 'block';
      setTimeout(() => {
        targetSection.classList.add('visible');
      }, 10);
      
      // Scroll to section
      targetSection.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    });
  });

  // Dynamic gradient based on mouse movement
  const gradient = document.querySelector('.cyber-gradient');
  document.addEventListener('mousemove', (e) => {
    const x = e.clientX / window.innerWidth;
    const y = e.clientY / window.innerHeight;
    gradient.style.background = 
      `linear-gradient(${135 + x * 45}deg, rgba(0, 247, 255, 0.05) 0%, transparent 50%),
       linear-gradient(${-135 + y * 45}deg, rgba(255, 0, 247, 0.05) 0%, transparent 50%)`;
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
      execute: () => 'Roman Orłowski - Cybersecurity Expert'
    },
    skills: {
      execute: () => `Core Skills:
  • Cloud Security (Azure, AWS)
  • Threat Analysis & Detection
  • Network Security & Zero Trust
  • Compliance (ISO 27001, GDPR, NIST)
  • Ethical Hacking (CEH)
  • Privacy Protection`
    },
    nmap: {
      execute: () => `Starting Nmap 7.92 scan...
Scanning target 192.168.1.1...
Discovered open port 80/tcp on target
Discovered open port 443/tcp on target
Discovered open port 22/tcp on target
Nmap scan report complete.`
    },
    msfconsole: {
      execute: () => `Starting Metasploit Framework console...
       =[ metasploit v6.2.0                  ]
+ -- --=[ 2200 exploits - 1171 auxiliary   ]
+ -- --=[ 400 post modules - 596 payloads  ]

msf6 > use exploit/multi/http/example
msf6 exploit(multi/http/example) > 
Remember: Use ethically for testing only.`
    },
    searchsploit: {
      execute: () => `Searching Exploit-DB...
Results:
  [1] Windows - Remote Code Execution (CVE-2021-xxxxx)
  [2] Linux - Privilege Escalation (CVE-2021-xxxxx)
  [3] Apache - Directory Traversal (CVE-2020-xxxxx)
Report vulnerabilities responsibly.`
    },
    ceh_phases: {
      execute: () => `CEH Ethical Hacking Phases:
  1. Reconnaissance - Information gathering
  2. Scanning - Port scanning and enumeration
  3. Gaining Access - Exploiting vulnerabilities
  4. Maintaining Access - Persistence mechanisms
  5. Covering Tracks - Log cleaning and evasion
Focus on defense and ethical use.`
    },
    privacy_tip: {
      execute: () => `Privacy Protection Tip:
Use encryption (e.g., VPNs, HTTPS) for all communications.
Enable MFA (Multi-Factor Authentication) on all accounts.
Comply with GDPR for privacy-by-design.
Minimize data collection and implement data retention policies.`
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
  const headerText = document.querySelector('.header h1');
  if (headerText) {
    const letters = headerText.querySelectorAll('.letter');
    letters.forEach((letter, index) => {
      letter.style.animationDelay = `${index * 0.1}s`;
    });
  }

  // Skill card hover effects
  const skillCards = document.querySelectorAll('.skill-card, .cert-card, .tool-card, .attribute-card');
  skillCards.forEach(card => {
    card.addEventListener('mouseenter', function() {
      this.style.transform = 'translateY(-5px) scale(1.02)';
    });
    
    card.addEventListener('mouseleave', function() {
      this.style.transform = 'translateY(0) scale(1)';
    });
  });

  // Matrix cell interactions
  const matrixCells = document.querySelectorAll('.matrix-cell');
  matrixCells.forEach(cell => {
    cell.addEventListener('mouseenter', function() {
      this.style.transform = 'scale(1.05)';
    });
    
    cell.addEventListener('mouseleave', function() {
      this.style.transform = 'scale(1)';
    });
  });

  // Timeline item animations
  const timelineItems = document.querySelectorAll('.timeline-item');
  timelineItems.forEach((item, index) => {
    item.style.animationDelay = `${index * 0.2}s`;
  });

  // Add glow effect to buttons on hover
  const cyberButtons = document.querySelectorAll('.cyber-button');
  cyberButtons.forEach(button => {
    button.addEventListener('mouseenter', function() {
      this.style.boxShadow = '0 10px 30px rgba(0, 247, 255, 0.4)';
    });
    
    button.addEventListener('mouseleave', function() {
      this.style.boxShadow = '0 4px 15px rgba(0, 247, 255, 0.2)';
    });
  });

  // Checklist item animations
  const checklistItems = document.querySelectorAll('.checklist-item');
  checklistItems.forEach((item, index) => {
    item.style.opacity = '0';
    item.style.transform = 'translateX(-20px)';
    setTimeout(() => {
      item.style.transition = 'all 0.5s ease';
      item.style.opacity = '1';
      item.style.transform = 'translateX(0)';
    }, index * 100);
  });

  // Framework card animations
  const frameworkCards = document.querySelectorAll('.framework-card');
  frameworkCards.forEach((card, index) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(20px)';
    setTimeout(() => {
      card.style.transition = 'all 0.5s ease';
      card.style.opacity = '1';
      card.style.transform = 'translateY(0)';
    }, index * 150);
  });

  // Architecture item pulse effect
  const architectureItems = document.querySelectorAll('.architecture-item');
  architectureItems.forEach((item, index) => {
    setTimeout(() => {
      item.style.animation = `pulse 2s ease-in-out infinite`;
      item.style.animationDelay = `${index * 0.2}s`;
    }, 1000);
  });

  // Add random glitch effect to header occasionally
  setInterval(() => {
    const headerTitle = document.querySelector('.header h1');
    if (headerTitle && Math.random() > 0.7) {
      headerTitle.style.animation = 'glitch 0.3s';
      setTimeout(() => {
        headerTitle.style.animation = '';
      }, 300);
    }
  }, 5000);

  // Scanline animation speed variation
  const scanlines = document.querySelector('.scanlines');
  if (scanlines) {
    setInterval(() => {
      const speed = 5 + Math.random() * 10;
      scanlines.style.animation = `scanline ${speed}s linear infinite`;
    }, 10000);
  }

  // Add particle burst effect on section click
  sections.forEach(section => {
    section.addEventListener('click', function(e) {
      if (e.target === this || e.target.tagName === 'H2') {
        const burst = document.createElement('div');
        burst.style.position = 'absolute';
        burst.style.width = '10px';
        burst.style.height = '10px';
        burst.style.borderRadius = '50%';
        burst.style.background = 'var(--primary)';
        burst.style.left = e.offsetX + 'px';
        burst.style.top = e.offsetY + 'px';
        burst.style.pointerEvents = 'none';
        burst.style.animation = 'pulse 0.5s ease-out forwards';
        this.appendChild(burst);
        
        setTimeout(() => {
          burst.remove();
        }, 500);
      }
    });
  });

  // Console welcome message
  console.log('%c🔒 ROCyber Solutions', 'color: #00f7ff; font-size: 24px; font-weight: bold;');
  console.log('%cWelcome to the cybersecurity portfolio of Roman Orłowski', 'color: #00ffaa; font-size: 14px;');
  console.log('%cInterested in cybersecurity? Check out the resources section!', 'color: #ff00f7; font-size: 12px;');
});

// Prevent right-click context menu (optional security feature)
// Uncomment if needed
// document.addEventListener('contextmenu', e => e.preventDefault());

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
  // Ctrl + K to focus terminal
  if (e.ctrlKey && e.key === 'k') {
    e.preventDefault();
    const terminalCommand = document.getElementById('terminal-command');
    if (terminalCommand) {
      terminalCommand.focus();
      document.getElementById('terminal').scrollIntoView({ behavior: 'smooth' });
    }
  }
  
  // Escape to clear terminal
  if (e.key === 'Escape') {
    const terminalCommand = document.getElementById('terminal-command');
    if (terminalCommand && document.activeElement === terminalCommand) {
      terminalCommand.value = '';
    }
  }
});

// Performance monitoring
window.addEventListener('load', function() {
  const loadTime = performance.now();
  console.log(`%cPage loaded in ${loadTime.toFixed(2)}ms`, 'color: #00ffaa;');
});




// Handle unified attributes navigation
document.addEventListener('DOMContentLoaded', function() {
  const navItems = document.querySelectorAll('.nav-item');
  
  navItems.forEach(item => {
    item.addEventListener('click', function() {
      const sectionId = this.getAttribute('data-section');
      
      // If clicking on abilities or management, show the personality section (unified)
      if (sectionId === 'abilities' || sectionId === 'management') {
        const personalityNav = document.querySelector('.nav-item[data-section="personality"]');
        if (personalityNav) {
          personalityNav.click();
        }
      }
    });
  });

  // Add random glitch effect to keywords
  const keywords = document.querySelectorAll('.keyword');
  keywords.forEach((keyword, index) => {
    setInterval(() => {
      if (Math.random() > 0.95) {
        keyword.style.animation = 'keywordShock 0.3s ease';
        setTimeout(() => {
          keyword.style.animation = 'keywordPulse 3s ease-in-out infinite';
        }, 300);
      }
    }, 3000 + index * 500);
  });

  // Add data stream effect to tron panels
  const tronPanels = document.querySelectorAll('.tron-panel');
  tronPanels.forEach((panel, index) => {
    panel.addEventListener('mouseenter', function() {
      const bullets = this.querySelectorAll('.bullet');
      bullets.forEach((bullet, i) => {
        setTimeout(() => {
          bullet.style.animation = 'bulletPulse 0.5s ease';
          setTimeout(() => {
            bullet.style.animation = 'bulletPulse 2s ease-in-out infinite';
          }, 500);
        }, i * 50);
      });
    });
  });

  // Add scanning line effect to unified attributes section
  const unifiedSection = document.querySelector('.unified-attributes');
  if (unifiedSection) {
    const scanLine = document.createElement('div');
    scanLine.style.position = 'absolute';
    scanLine.style.top = '0';
    scanLine.style.left = '0';
    scanLine.style.width = '100%';
    scanLine.style.height = '2px';
    scanLine.style.background = 'linear-gradient(90deg, transparent, var(--primary), transparent)';
    scanLine.style.boxShadow = '0 0 20px var(--primary)';
    scanLine.style.animation = 'scanDown 5s linear infinite';
    scanLine.style.pointerEvents = 'none';
    scanLine.style.zIndex = '10';
    unifiedSection.appendChild(scanLine);

    // Add scan animation
    const style = document.createElement('style');
    style.textContent = `
      @keyframes scanDown {
        0% {
          top: 0;
          opacity: 0;
        }
        10% {
          opacity: 1;
        }
        90% {
          opacity: 1;
        }
        100% {
          top: 100%;
          opacity: 0;
        }
      }
    `;
    document.head.appendChild(style);
  }

  // Enhanced keyword interactions
  keywords.forEach(keyword => {
    keyword.addEventListener('click', function() {
      // Create ripple effect
      const ripple = document.createElement('span');
      ripple.style.position = 'absolute';
      ripple.style.width = '100%';
      ripple.style.height = '100%';
      ripple.style.top = '0';
      ripple.style.left = '0';
      ripple.style.background = 'radial-gradient(circle, var(--primary) 0%, transparent 70%)';
      ripple.style.transform = 'scale(0)';
      ripple.style.animation = 'rippleEffect 0.6s ease-out';
      ripple.style.pointerEvents = 'none';
      this.appendChild(ripple);

      setTimeout(() => {
        ripple.remove();
      }, 600);
    });
  });

  // Add ripple animation
  const rippleStyle = document.createElement('style');
  rippleStyle.textContent = `
    @keyframes rippleEffect {
      to {
        transform: scale(4);
        opacity: 0;
      }
    }
  `;
  document.head.appendChild(rippleStyle);

  // Add matrix rain effect to profile section on hover
  const profileSection = document.getElementById('profile');
  if (profileSection) {
    profileSection.addEventListener('mouseenter', function() {
      // Trigger keyword animations in sequence
      const keywords = this.querySelectorAll('.keyword');
      keywords.forEach((keyword, index) => {
        setTimeout(() => {
          keyword.style.transform = 'scale(1.05)';
          keyword.style.boxShadow = '0 0 15px currentColor';
          setTimeout(() => {
            keyword.style.transform = '';
            keyword.style.boxShadow = '';
          }, 200);
        }, index * 50);
      });
    });
  }
});

