// Security headers and performance optimization
(function() {
    'use strict';
    
    // Add security headers
    const metaCSP = document.createElement('meta');
    metaCSP.httpEquiv = "Content-Security-Policy";
    metaCSP.content = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.youtube.com 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; connect-src 'self' https:; frame-src https://www.youtube.com; frame-ancestors 'none'; form-action 'self'; base-uri 'self';";
    document.head.appendChild(metaCSP);

    // Lazy loading for images
    const images = document.querySelectorAll('img');
    images.forEach(img => {
        img.loading = 'lazy';
        img.decoding = 'async';
    });

    // Performance monitoring
    if ('performance' in window) {
        window.addEventListener('load', function() {
            const loadTime = performance.now();
            console.log(`%c🚀 Page loaded in ${loadTime.toFixed(2)}ms`, 'color: #00ffaa; font-weight: bold;');
            
            // Core Web Vitals
            if ('web-vitals' in window) {
                getCLS(console.log);
                getFID(console.log);
                getLCP(console.log);
            }
        });
    }
})();

// Dark mode functionality
const darkModeToggle = document.getElementById('dark-mode-toggle');
const body = document.body;

// Check for saved dark mode preference
const savedDarkMode = localStorage.getItem('darkMode');
if (savedDarkMode === 'enabled') {
    body.classList.add('dark-mode');
    darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
}

darkModeToggle.addEventListener('click', () => {
    body.classList.toggle('dark-mode');
    
    if (body.classList.contains('dark-mode')) {
        localStorage.setItem('darkMode', 'enabled');
        darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    } else {
        localStorage.setItem('darkMode', 'disabled');
        darkModeToggle.innerHTML = '<i class="fas fa-moon"></i>';
    }
});

// Particles.js Configuration
function initializeParticles() {
    if (typeof particlesJS !== 'undefined') {
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
    }
}

// Music Player with error handling
let isPlaying = false;
let currentVideo = '9RJVuT9Y_2k';
let player = null;

function initializeMusicPlayer() {
    const playBtn = document.getElementById('play-btn');
    const prevBtn = document.getElementById('prev-btn');
    const nextBtn = document.getElementById('next-btn');
    const volumeBtn = document.getElementById('volume-btn');
    const playerHeader = document.getElementById('player-header');
    const playlistItems = document.querySelectorAll('.playlist-item');
    
    // Load YouTube IFrame API with error handling
    if (typeof YT === 'undefined') {
        const tag = document.createElement('script');
        tag.src = "https://www.youtube.com/iframe_api";
        tag.onerror = () => {
            console.warn('YouTube API failed to load. Music player disabled.');
            document.querySelector('.music-player').style.display = 'none';
        };
        const firstScriptTag = document.getElementsByTagName('script')[0];
        firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
    }
    
    window.onYouTubeIframeAPIReady = function() {
        try {
            player = new YT.Player('youtube-player', {
                height: '0',
                width: '0',
                videoId: currentVideo,
                playerVars: {
                    'autoplay': 0,
                    'controls': 0,
                    'showinfo': 0,
                    'rel': 0,
                    'modestbranding': 1
                },
                events: {
                    'onReady': onPlayerReady,
                    'onStateChange': onPlayerStateChange,
                    'onError': onPlayerError
                }
            });
        } catch (error) {
            console.warn('YouTube player initialization failed:', error);
            document.querySelector('.music-player').style.display = 'none';
        }
    };
    
    function onPlayerReady(event) {
        event.target.setVolume(30);
    }
    
    function onPlayerStateChange(event) {
        if (event.data == YT.PlayerState.PLAYING) {
            isPlaying = true;
            playBtn.innerHTML = '<i class="fas fa-pause"></i>';
        } else {
            isPlaying = false;
            playBtn.innerHTML = '<i class="fas fa-play"></i>';
        }
    }
    
    function onPlayerError(event) {
        console.warn('YouTube player error:', event.data);
        document.querySelector('.music-player').style.display = 'none';
    }
    
    playBtn.addEventListener('click', function() {
        if (!player) return;
        
        try {
            if (isPlaying) {
                player.pauseVideo();
                this.innerHTML = '<i class="fas fa-play"></i>';
            } else {
                player.playVideo();
                this.innerHTML = '<i class="fas fa-pause"></i>';
            }
            isPlaying = !isPlaying;
        } catch (error) {
            console.warn('Player control failed:', error);
        }
    });
    
    prevBtn.addEventListener('click', function() {
        const items = Array.from(playlistItems);
        const currentIndex = items.findIndex(item => item.classList.contains('active'));
        const prevIndex = (currentIndex - 1 + items.length) % items.length;
        
        changeTrack(items[prevIndex].dataset.video);
        updateActivePlaylistItem(prevIndex);
    });
    
    nextBtn.addEventListener('click', function() {
        const items = Array.from(playlistItems);
        const currentIndex = items.findIndex(item => item.classList.contains('active'));
        const nextIndex = (currentIndex + 1) % items.length;
        
        changeTrack(items[nextIndex].dataset.video);
        updateActivePlaylistItem(nextIndex);
    });
    
    volumeBtn.addEventListener('click', function() {
        if (!player) return;
        
        try {
            const currentVolume = player.getVolume();
            if (currentVolume > 0) {
                player.setVolume(0);
                this.innerHTML = '<i class="fas fa-volume-mute"></i>';
            } else {
                player.setVolume(30);
                this.innerHTML = '<i class="fas fa-volume-up"></i>';
            }
        } catch (error) {
            console.warn('Volume control failed:', error);
        }
    });
    
    playerHeader.addEventListener('click', function() {
        const playerBody = document.querySelector('.player-body');
        const musicPlayer = document.getElementById('music-player');
        
        if (playerBody.style.display === 'none') {
            playerBody.style.display = 'block';
            musicPlayer.classList.remove('collapsed');
        } else {
            playerBody.style.display = 'none';
            musicPlayer.classList.add('collapsed');
        }
    });
    
    playlistItems.forEach((item, index) => {
        item.addEventListener('click', function() {
            const videoId = this.dataset.video;
            changeTrack(videoId);
            updateActivePlaylistItem(index);
            
            if (!isPlaying && player) {
                player.playVideo();
                isPlaying = true;
                playBtn.innerHTML = '<i class="fas fa-pause"></i>';
            }
        });
    });
    
    function changeTrack(videoId) {
        currentVideo = videoId;
        if (player) {
            player.loadVideoById(videoId);
            updateTrackInfo(videoId);
        }
    }
    
    function updateActivePlaylistItem(index) {
        playlistItems.forEach(item => item.classList.remove('active'));
        playlistItems[index].classList.add('active');
    }
    
    function updateTrackInfo(videoId) {
        const trackInfo = {
            '9RJVuT9Y_2k': {
                title: 'Cyberpunk Synthwave Mix',
                artist: 'Various Artists'
            },
            'm3h8e8vCc-s': {
                title: 'Hacker Coding Music',
                artist: 'Programming Mix'
            },
            'MVPTGNGiI-4': {
                title: 'Electronic Focus Music',
                artist: 'Deep Work Mix'
            }
        };
        
        const info = trackInfo[videoId];
        if (info) {
            document.querySelector('.track-title').textContent = info.title;
            document.querySelector('.track-artist').textContent = info.artist;
        }
    }
}

// Contact form with validation
function initializeContactForm() {
    const contactForm = document.getElementById('contact-form');
    const formFeedback = document.getElementById('form-feedback');
    
    if (!contactForm) return;
    
    contactForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(contactForm);
        const name = formData.get('name').trim();
        const email = formData.get('email').trim();
        const subject = formData.get('subject').trim();
        const message = formData.get('message').trim();
        
        // Validation
        if (!name || !email || !subject || !message) {
            showFormFeedback('Please fill in all required fields.', 'error');
            return;
        }
        
        if (!validateEmail(email)) {
            showFormFeedback('Please enter a valid email address.', 'error');
            return;
        }
        
        if (message.length < 10) {
            showFormFeedback('Message must be at least 10 characters long.', 'error');
            return;
        }
        
        // Simulate form submission
        showFormFeedback('Sending message...', 'info');
        
        setTimeout(() => {
            showFormFeedback('Message sent successfully! I will get back to you soon.', 'success');
            contactForm.reset();
        }, 2000);
    });
    
    function showFormFeedback(message, type) {
        formFeedback.textContent = message;
        formFeedback.className = `form-feedback ${type}`;
        
        setTimeout(() => {
            formFeedback.textContent = '';
            formFeedback.className = 'form-feedback';
        }, 5000);
    }
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Intro Sequence
document.addEventListener('DOMContentLoaded', function() {
    const introSequence = document.getElementById('intro-sequence');
    
    setTimeout(() => {
        introSequence.style.display = 'none';
        initializeParticles();
    }, 5000);

    // Initialize components
    initializeMusicPlayer();
    initializeContactForm();

    // Intersection Observer for sections
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                animateTimelineItems();
            }
        });
    }, observerOptions);

    document.querySelectorAll('.section').forEach(section => {
        observer.observe(section);
    });

    // Navigation with keyboard support
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.section');

    navItems.forEach(item => {
        item.addEventListener('click', function() {
            navigateToSection(this);
        });
        
        item.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                navigateToSection(this);
            }
        });
    });
    
    function navigateToSection(navItem) {
        // Remove active class from all nav items
        navItems.forEach(nav => nav.classList.remove('active'));
        navItems.forEach(nav => nav.setAttribute('aria-pressed', 'false'));
        
        // Add active class to clicked item
        navItem.classList.add('active');
        navItem.setAttribute('aria-pressed', 'true');
        
        // Hide all sections
        sections.forEach(section => {
            section.classList.remove('visible');
            section.style.display = 'none';
        });
        
        // Show selected section
        const sectionId = navItem.getAttribute('data-section');
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
    }

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
  experience    - Show professional experience
  nmap          - Simulate network scan
  msfconsole    - Launch Metasploit console
  searchsploit  - Search exploit database
  ceh_phases    - Display CEH hacking phases
  privacy_tip   - Get privacy protection tip
  disclosure    - Learn about responsible disclosure
  clear         - Clear terminal output`
        },
        whoami: {
            execute: () => 'Roman Orłowski - Cybersecurity Expert | 15+ years experience in IT & Security'
        },
        skills: {
            execute: () => `Core Skills:
  • Cloud Security (Azure, AWS, GCP)
  • Threat Analysis & Detection (SIEM, EDR)
  • Network Security & Zero Trust Architecture
  • Compliance (ISO 27001, GDPR, NIST, SOX)
  • Ethical Hacking & Penetration Testing
  • Privacy Protection & Data Security
  • Incident Response & Digital Forensics
  • OSINT & Threat Intelligence Gathering`
        },
        experience: {
            execute: () => `Professional Timeline:
  2024-Present: Freelance Cybersecurity Consultant
  2023-2024: Senior Engineer - LTIMINDTREE
  2022-2023: Support Engineer - Intellias
  2021: IT Specialist - Cinema City
  2020-2021: Platform Engineer - Discovery
  2020: NOC Engineer - Sperasoft (Amazon New World)
  2019-2020: EOC Analyst - Grand Parade/William Hill
  2018-2019: Network Specialist - Emitel SA
  2015-2017: NOC Specialist - Horsebridge Networks
  2011-2014: Telecom Engineer - Openreach
  2006-2010: IT Support - First Red Midland Buses`
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
• Use encryption (VPNs, HTTPS) for all communications
• Enable MFA (Multi-Factor Authentication) on all accounts
• Comply with GDPR for privacy-by-design
• Minimize data collection and implement retention policies
• Regular security awareness training`
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

    // Quiz Functionality with keyboard support
    const quizOptions = document.querySelectorAll('.quiz-option');
    quizOptions.forEach(option => {
        option.addEventListener('click', function() {
            handleQuizAnswer(this);
        });
        
        option.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleQuizAnswer(this);
            }
        });
    });
    
    function handleQuizAnswer(selectedOption) {
        const question = selectedOption.closest('.quiz-question');
        const feedback = question.querySelector('.quiz-feedback');
        const isCorrect = selectedOption.dataset.correct === 'true';
        
        // Remove previous selections
        question.querySelectorAll('.quiz-option').forEach(opt => {
            opt.style.background = 'rgba(20, 20, 30, 0.5)';
            opt.style.borderColor = 'rgba(0, 247, 255, 0.1)';
        });
        
        // Highlight selected option
        if (isCorrect) {
            selectedOption.style.background = 'rgba(85, 255, 85, 0.2)';
            selectedOption.style.borderColor = 'var(--low)';
            feedback.textContent = '✓ Correct! Great job!';
            feedback.className = 'quiz-feedback correct';
        } else {
            selectedOption.style.background = 'rgba(255, 85, 85, 0.2)';
            selectedOption.style.borderColor = 'var(--critical)';
            feedback.textContent = '✗ Incorrect. Try again!';
            feedback.className = 'quiz-feedback incorrect';
        }
    }

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

    // Timeline animation
    function animateTimelineItems() {
        const timelineItems = document.querySelectorAll('.timeline-item');
        timelineItems.forEach((item, index) => {
            setTimeout(() => {
                item.style.animationDelay = `${index * 0.1}s`;
                item.style.animation = 'slideInRight 0.5s forwards';
            }, 100);
        });
    }

    // Initialize timeline animation
    animateTimelineItems();

    // Keyword hover effects
    const keywords = document.querySelectorAll('.keyword');
    keywords.forEach(keyword => {
        keyword.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.05)';
            this.style.boxShadow = '0 0 20px currentColor';
        });
        
        keyword.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
            this.style.boxShadow = 'none';
        });
    });

    // Hobby item animations
    const hobbyItems = document.querySelectorAll('.hobby-item');
    hobbyItems.forEach((item, index) => {
        item.style.animationDelay = `${index * 0.1}s`;
        item.style.animation = 'fadeInUp 0.5s forwards';
    });

    // Skill card hover effects
    const skillCards = document.querySelectorAll('.skill-card, .cert-card, .tool-card, .education-card');
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

    // Random keyword glitch effect
    setInterval(() => {
        const keywords = document.querySelectorAll('.keyword');
        if (keywords.length > 0 && Math.random() > 0.9) {
            const randomKeyword = keywords[Math.floor(Math.random() * keywords.length)];
            randomKeyword.style.animation = 'keywordShock 0.3s ease';
            setTimeout(() => {
                randomKeyword.style.animation = 'keywordPulse 3s ease-in-out infinite';
            }, 300);
        }
    }, 5000);

    // Console welcome message
    console.log('%c🔒 ROCyber Solutions', 'color: #00f7ff; font-size: 24px; font-weight: bold;');
    console.log('%cWelcome to the cybersecurity portfolio of Roman Orłowski', 'color: #00ffaa; font-size: 14px;');
    console.log('%c15+ years of IT & Cybersecurity experience | CISSP | CISM | CISA', 'color: #ff00f7; font-size: 12px;');
    console.log('%cInterested in cybersecurity? Check out the resources section!', 'color: #00f7ff; font-size: 12px;');

    // Service Worker registration for offline functionality
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('sw.js').catch(err => {
                console.log('Service Worker registration failed:', err);
            });
        });
    }
});

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
    
    // Space to toggle music player (only when not typing)
    if (e.key === ' ' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
        e.preventDefault();
        const playBtn = document.getElementById('play-btn');
        if (playBtn) playBtn.click();
    }
    
    // Escape to clear terminal
    if (e.key === 'Escape') {
        const terminalCommand = document.getElementById('terminal-command');
        if (terminalCommand && document.activeElement === terminalCommand) {
            terminalCommand.value = '';
        }
    }
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
});

// Error handling for failed resources
window.addEventListener('error', function(e) {
    console.warn('Resource failed to load:', e.filename || e.target.src);
    
    // Fallback for failed YouTube embed
    if (e.target.tagName === 'IFRAME' && e.target.src.includes('youtube')) {
        const musicPlayer = document.querySelector('.music-player');
        if (musicPlayer) {
            musicPlayer.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--primary);">Music player unavailable</div>';
        }
    }
}, true);
