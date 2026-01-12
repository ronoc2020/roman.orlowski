// Global variables for YouTube API
let ytPlayer1, ytPlayer2, currentTrack = 0;
const tracks = [
  { name: "Cyberpunk Mix - Mega Drive", id: "VwXHT8HwgIs" },
  { name: "Synthwave Mix - Lazerhawk", id: "uEFFrIW0buE" }
];

// Initialize particles.js
document.addEventListener('DOMContentLoaded', function() {
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

  // Hide intro sequence
  const introSequence = document.getElementById('intro-sequence');
  setTimeout(() => {
    introSequence.style.display = 'none';
  }, 5000);

  // Initialize audio player
  initAudioPlayer();

  // Initialize lazy loading
  initLazyLoading();

  // Initialize navigation
  initNavigation();

  // Initialize terminal
  initTerminal();

  // Initialize quiz
  initQuiz();

  // Initialize contact form
  initContactForm();

  // Initialize animations
  initAnimations();

  // Initialize parallax effects
  initParallax();

  // Console welcome message
  console.log('%c🔒 ROCyber Solutions', 'color: #00f7ff; font-size: 24px; font-weight: bold;');
  console.log('%cWelcome to the cybersecurity portfolio of Roman Orłowski', 'color: #00ffaa; font-size: 14px;');
  console.log('%cInterested in cybersecurity? Check out the resources section!', 'color: #ff00f7; font-size: 12px;');
  console.log('%cKeyboard shortcuts: Ctrl+K (focus terminal), Esc (clear terminal)', 'color: #55ff55; font-size: 11px;');
});

// YouTube API Ready
function onYouTubeIframeAPIReady() {
  ytPlayer1 = new YT.Player('yt-player-1', {
    events: {
      'onStateChange': onPlayerStateChange
    }
  });
  ytPlayer2 = new YT.Player('yt-player-2', {
    events: {
      'onStateChange': onPlayerStateChange
    }
  });
}

function onPlayerStateChange(event) {
  if (event.data === YT.PlayerState.ENDED) {
    playNextTrack();
  }
}

// Audio Player Functions
function initAudioPlayer() {
  const player = document.getElementById('audio-player');
  const playBtn = document.getElementById('play-btn');
  const pauseBtn = document.getElementById('pause-btn');
  const nextBtn = document.getElementById('next-btn');
  const closeBtn = document.getElementById('close-btn');
  const progressFill = document.getElementById('progress-fill');

  // Show player after intro
  setTimeout(() => {
    player.classList.add('visible');
  }, 6000);

  // Auto-play first track
  setTimeout(() => {
    playTrack(0);
  }, 7000);

  playBtn.addEventListener('click', () => playTrack(currentTrack));
  pauseBtn.addEventListener('click', pauseAllTracks);
  nextBtn.addEventListener('click', playNextTrack);
  closeBtn.addEventListener('click', () => {
    player.style.display = 'none';
  });

  // Simulate progress
  setInterval(updateProgress, 1000);
}

function playTrack(index) {
  const track = tracks[index];
  document.getElementById('track-name').textContent = track.name;
  currentTrack = index;

  // Hide all players
  if (ytPlayer1) ytPlayer1.pauseVideo();
  if (ytPlayer2) ytPlayer2.pauseVideo();

  // Play selected track (YouTube API requires manual interaction first)
  if (index === 0 && ytPlayer1) {
    ytPlayer1.playVideo();
  } else if (index === 1 && ytPlayer2) {
    ytPlayer2.playVideo();
  }

  document.getElementById('play-btn').style.display = 'none';
  document.getElementById('pause-btn').style.display = 'flex';
}

function playNextTrack() {
  const nextIndex = (currentTrack + 1) % tracks.length;
  playTrack(nextIndex);
}

function pauseAllTracks() {
  if (ytPlayer1) ytPlayer1.pauseVideo();
  if (ytPlayer2) ytPlayer2.pauseVideo();
  document.getElementById('play-btn').style.display = 'flex';
  document.getElementById('pause-btn').style.display = 'none';
}

function updateProgress() {
  const progressFill = document.getElementById('progress-fill');
  let progress = 0;
  
  if (currentTrack === 0 && ytPlayer1 && ytPlayer1.getCurrentTime) {
    progress = (ytPlayer1.getCurrentTime() / ytPlayer1.getDuration()) * 100;
  } else if (currentTrack === 1 && ytPlayer2 && ytPlayer2.getCurrentTime) {
    progress = (ytPlayer2.getCurrentTime() / ytPlayer2.getDuration()) * 100;
  }
  
  progressFill.style.width = progress + '%';
}

// Lazy Loading Initialization
function initLazyLoading() {
  const lazySections = document.querySelectorAll('[data-lazy]');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const section = entry.target;
        section.classList.add('loading');
        
        // Simulate loading delay
        setTimeout(() => {
          section.classList.remove('loading');
          section.classList.add('loaded');
          section.classList.add('visible');
          
          // Apply animation based on data attribute
          const animationType = section.getAttribute('data-lazy');
          section.style.animation = `${animationType} 0.6s ease forwards`;
          
          observer.unobserve(section);
        }, 300);
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
  });

  lazySections.forEach(section => {
    observer.observe(section);
  });
}

// Navigation
function initNavigation() {
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
      
      // Handle unified attributes section
      if (sectionId === 'abilities' || sectionId === 'management') {
        document.querySelector('.nav-item[data-section="personality"]').click();
        return;
      }
      
      const targetSection = document.getElementById(sectionId);
      if (targetSection) {
        targetSection.style.display = 'block';
        setTimeout(() => {
          targetSection.classList.add('visible');
        }, 10);
        
        // Scroll to section with offset for nav
        const navHeight = document.querySelector('.nav').offsetHeight;
        const sectionTop = targetSection.offsetTop - navHeight - 20;
        window.scrollTo({
          top: sectionTop,
          behavior: 'smooth'
        });
      }
    });
  });
}

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

function initTerminal() {
  const terminalCommand = document.getElementById('terminal-command');
  const terminalOutput = document.getElementById('terminal-output');
  
  if (!terminalCommand || !terminalOutput) return;

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

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'k') {
      e.preventDefault();
      terminalCommand.focus();
      document.getElementById('terminal').scrollIntoView({ behavior: 'smooth' });
    }
    
    if (e.key === 'Escape' && document.activeElement === terminalCommand) {
      terminalCommand.value = '';
    }
  });
}

function initQuiz() {
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

      // Calculate score
      updateQuizScore();
    });
  });
}

function updateQuizScore() {
  const questions = document.querySelectorAll('.quiz-question');
  const correctAnswers = document.querySelectorAll('.quiz-option[data-correct="true"]');
  const selectedCorrect = document.querySelectorAll('.quiz-option[data-correct="true"][style*="rgba(85, 255, 85"]');
  
  if (questions.length === selectedCorrect.length) {
    const resultsDiv = document.getElementById('quiz-results');
    resultsDiv.innerHTML = `
      <div class="quiz-score">
        <h3>Quiz Complete!</h3>
        <p>Score: ${selectedCorrect.length}/${questions.length} - Perfect!</p>
        <button class="cyber-button futurist-btn" onclick="resetQuiz()">Retake Quiz</button>
      </div>
    `;
  }
}

function resetQuiz() {
  document.querySelectorAll('.quiz-option').forEach(opt => {
    opt.style.background = 'rgba(20, 20, 30, 0.5)';
    opt.style.borderColor = 'rgba(0, 247, 255, 0.1)';
  });
  document.querySelectorAll('.quiz-feedback').forEach(feedback => {
    feedback.textContent = '';
    feedback.className = 'quiz-feedback';
  });
  document.getElementById('quiz-results').innerHTML = '';
}

function initContactForm() {
  const form = document.getElementById('contact-form');
  if (!form) return;

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Simulate form submission
    const button = form.querySelector('button');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
    button.disabled = true;

    setTimeout(() => {
      button.innerHTML = '<i class="fas fa-check"></i> Message Sent!';
      button.style.background = 'var(--low)';
      
      setTimeout(() => {
        button.innerHTML = originalText;
        button.disabled = false;
        button.style.background = '';
        form.reset();
      }, 2000);
    }, 1500);
  });
}

function initAnimations() {
  // Add typing effect to header
  const headerText = document.querySelector('.header h1');
  if (headerText) {
    const letters = headerText.querySelectorAll('.letter');
    letters.forEach((letter, index) => {
      letter.style.animationDelay = `${index * 0.1}s`;
    });
  }

  // Animate timeline items with delay
  const timelineItems = document.querySelectorAll('.timeline-item');
  timelineItems.forEach((item, index) => {
    item.style.animationDelay = `${index * 0.2}s`;
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

  // Animate skill cards on load
  animateOnLoad('.skill-card', 200);
  animateOnLoad('.cert-card', 250);
  animateOnLoad('.tool-card', 300);
}

function animateOnLoad(selector, delay) {
  const elements = document.querySelectorAll(selector);
  elements.forEach((el, index) => {
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(20px)';
      el.style.transition = 'all 0.6s ease';
      
      setTimeout(() => {
        el.style.opacity = '1';
        el.style.transform = 'translateY(0)';
      }, 100);
    }, index * delay);
  });
}

function initParallax() {
  // Parallax for floating elements
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
    
    // Dynamic gradient
    const gradient = document.querySelector('.cyber-gradient');
    if (gradient) {
      gradient.style.background = 
        `linear-gradient(${135 + mouseX * 45}deg, rgba(0, 247, 255, 0.05) 0%, transparent 50%),
         linear-gradient(${-135 + mouseY * 45}deg, rgba(255, 0, 247, 0.05) 0%, transparent 50%)`;
    }
  });

  // Scroll parallax for header
  window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const header = document.querySelector('.header');
    if (header) {
      header.style.transform = `translateY(${scrolled * 0.5}px)`;
      header.style.opacity = 1 - (scrolled / 500);
    }
  });
}

// Performance monitoring
window.addEventListener('load', function() {
  const loadTime = performance.now();
  console.log(`%cPage loaded in ${loadTime.toFixed(2)}ms`, 'color: #00ffaa;');
  
  // Report Core Web Vitals
  if ('web-vital' in window) {
    webVital.getCLS(console.log);
    webVital.getFID(console.log);
    webVital.getLCP(console.log);
  }
});

// Handle unified attributes navigation
document.addEventListener('DOMContentLoaded', function() {
  // Add ripple effect to keywords
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

  // Add scanning line effect to unified attributes section
  const unifiedSection = document.querySelector('.unified-attributes');
  if (unifiedSection && !unifiedSection.querySelector('.scan-down')) {
    const scanLine = document.createElement('div');
    scanLine.className = 'scan-down';
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
  }
});

// Add custom styles for ripple and scan effects
const style = document.createElement('style');
style.textContent = `
  @keyframes rippleEffect {
    to {
      transform: scale(4);
      opacity: 0;
    }
  }
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
  @keyframes keywordShock {
    0% { transform: scale(1); }
    50% { transform: scale(1.1); filter: brightness(1.5); }
    100% { transform: scale(1); }
  }
  @keyframes keywordPulse {
    0%, 100% { box-shadow: 0 0 0 rgba(0, 247, 255, 0.3); }
    50% { box-shadow: 0 0 15px rgba(0, 247, 255, 0.6); }
  }
`;
document.head.appendChild(style);

// Prevent right-click context menu (optional security feature)
// Uncomment if needed for professional presentation
/*
document.addEventListener('contextmenu', e => {
  e.preventDefault();
  console.log('%cContext menu disabled for security demonstration', 'color: #ffcc33;');
});
*/
