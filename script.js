// Security headers and performance optimization
(function() {
    'use strict';
    try {
        if (typeof document !== 'undefined' && document.head) {
            // Add security headers (best-effort; meta CSP only affects some scenarios)
            const metaCSP = document.createElement('meta');
            metaCSP.httpEquiv = "Content-Security-Policy";
            metaCSP.content = "default-src 'self'; " +
                              "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.youtube.com 'unsafe-inline'; " +
                              "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; " +
                              "img-src 'self' data: https:; " +
                              "font-src 'self' https://fonts.gstatic.com data:; " +
                              "connect-src 'self' https://api.github.com https://www.youtube.com; " +
                              "frame-src https://www.youtube.com https://www.youtube-nocookie.com; " +
                              "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';";
            document.head.appendChild(metaCSP);
        }
    } catch (err) {
        console.warn('Failed to add CSP meta tag:', err);
    }

    // Lazy loading for images
    try {
        const images = document.querySelectorAll && document.querySelectorAll('img') || [];
        images.forEach(img => {
            try {
                img.loading = 'lazy';
                img.decoding = 'async';
            } catch (e) { /* ignore per-image errors */ }
        });
    } catch (e) {
        // no-op
    }

    // Performance monitoring
    if (typeof window !== 'undefined' && 'performance' in window) {
        window.addEventListener('load', function() {
            try {
                const loadTime = performance.now();
                console.log(`%c🚀 Page loaded in ${loadTime.toFixed(2)}ms`, 'color: #00ffaa; font-weight: bold;');

                // Core Web Vitals (only if functions are available)
                if (typeof getCLS === 'function' || typeof getFID === 'function' || typeof getLCP === 'function') {
                    if (typeof getCLS === 'function') getCLS(console.log);
                    if (typeof getFID === 'function') getFID(console.log);
                    if (typeof getLCP === 'function') getLCP(console.log);
                }
            } catch (e) {
                console.warn('Performance monitoring error:', e);
            }
        });
    }
})();

// Dark mode functionality (guarded)
(function() {
    const darkModeToggle = document.getElementById && document.getElementById('dark-mode-toggle');
    const body = typeof document !== 'undefined' ? document.body : null;

    if (!body || !darkModeToggle) {
        return;
    }

    // Check for saved dark mode preference
    const savedDarkMode = localStorage.getItem('darkMode');
    if (savedDarkMode === 'enabled') {
        body.classList.add('dark-mode');
        try { darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>'; } catch (e) {}
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
})();

// Particles.js Configuration
function initializeParticles() {
    try {
        if (typeof particlesJS !== 'undefined' && typeof particlesJS === 'function') {
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
                        stroke: { width: 0, color: '#000000' }
                    },
                    opacity: { value: 0.5, random: false, anim: { enable: false } },
                    size: { value: 3, random: true, anim: { enable: false } },
                    line_linked: { enable: true, distance: 150, color: '#00f7ff', opacity: 0.4, width: 1 },
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
    } catch (e) {
        console.warn('initializeParticles error:', e);
    }
}

// Music Player with error handling
let isPlaying = false;
let currentVideo = '9RJVuT9Y_2k';
let player = null;

function initializeMusicPlayer() {
    const playBtn = document.getElementById && document.getElementById('play-btn');
    const prevBtn = document.getElementById && document.getElementById('prev-btn');
    const nextBtn = document.getElementById && document.getElementById('next-btn');
    const volumeBtn = document.getElementById && document.getElementById('volume-btn');
    const playerHeader = document.getElementById && document.getElementById('player-header');
    const playlistItems = document.querySelectorAll ? document.querySelectorAll('.playlist-item') : [];

    // If core UI missing, skip initialization
    const musicPlayerRoot = document.querySelector && document.querySelector('.music-player');
    if (!musicPlayerRoot) return;

    // Load YouTube IFrame API with error handling
    if (typeof YT === 'undefined') {
        try {
            const tag = document.createElement('script');
            tag.src = "https://www.youtube.com/iframe_api";
            tag.onerror = () => {
                console.warn('YouTube API failed to load. Music player disabled.');
                if (musicPlayerRoot) musicPlayerRoot.style.display = 'none';
            };
            const firstScriptTag = document.getElementsByTagName('script')[0];
            if (firstScriptTag && firstScriptTag.parentNode) {
                firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
            } else {
                document.head.appendChild(tag);
            }
        } catch (e) {
            console.warn('Failed to inject YouTube API script:', e);
        }
    }

    // Expose handler globally (YouTube API will call this)
    window.onYouTubeIframeAPIReady = function() {
        try {
            player = new YT.Player('youtube-player', {
                height: '0',
                width: '0',
                videoId: currentVideo,
                playerVars: {
                    'autoplay': 0,
                    'controls': 0,
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
            if (musicPlayerRoot) musicPlayerRoot.style.display = 'none';
        }
    };

    function onPlayerReady(event) {
        try { event.target.setVolume(30); } catch (e) {}
    }

    function onPlayerStateChange(event) {
        try {
            if (event.data == YT.PlayerState.PLAYING) {
                isPlaying = true;
                if (playBtn) playBtn.innerHTML = '<i class="fas fa-pause"></i>';
            } else {
                isPlaying = false;
                if (playBtn) playBtn.innerHTML = '<i class="fas fa-play"></i>';
            }
        } catch (e) { /* ignore */ }
    }

    function onPlayerError(event) {
        console.warn('YouTube player error:', event && event.data);
        if (musicPlayerRoot) {
            musicPlayerRoot.style.display = 'none';
        }
    }

    // Attach UI listeners only if elements exist
    if (playBtn) {
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
    }

    if (prevBtn) {
        prevBtn.addEventListener('click', function() {
            const items = Array.from(playlistItems || []);
            if (!items.length) return;
            const currentIndex = items.findIndex(item => item.classList.contains('active'));
            const prevIndex = (currentIndex - 1 + items.length) % items.length;
            changeTrack(items[prevIndex].dataset.video);
            updateActivePlaylistItem(prevIndex);
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', function() {
            const items = Array.from(playlistItems || []);
            if (!items.length) return;
            const currentIndex = items.findIndex(item => item.classList.contains('active'));
            const nextIndex = (currentIndex + 1) % items.length;
            changeTrack(items[nextIndex].dataset.video);
            updateActivePlaylistItem(nextIndex);
        });
    }

    if (volumeBtn) {
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
    }

    if (playerHeader) {
        playerHeader.addEventListener('click', function() {
            const playerBody = document.querySelector('.player-body');
            const musicPlayer = document.getElementById('music-player');

            if (!playerBody || !musicPlayer) return;

            if (playerBody.style.display === 'none') {
                playerBody.style.display = 'block';
                musicPlayer.classList.remove('collapsed');
            } else {
                playerBody.style.display = 'none';
                musicPlayer.classList.add('collapsed');
            }
        });
    }

    (playlistItems || []).forEach((item, index) => {
        item.addEventListener('click', function() {
            const videoId = this.dataset.video;
            if (!videoId) return;
            changeTrack(videoId);
            updateActivePlaylistItem(index);

            if (!isPlaying && player) {
                player.playVideo();
                isPlaying = true;
                if (playBtn) playBtn.innerHTML = '<i class="fas fa-pause"></i>';
            }
        });
    });

    function changeTrack(videoId) {
        if (!videoId) return;
        currentVideo = videoId;
        if (player) {
            try {
                player.loadVideoById(videoId);
                updateTrackInfo(videoId);
            } catch (e) {
                console.warn('changeTrack error:', e);
            }
        } else {
            updateTrackInfo(videoId);
        }
    }

    function updateActivePlaylistItem(index) {
        (playlistItems || []).forEach(item => item.classList.remove('active'));
        if ((playlistItems || [])[index]) (playlistItems || [])[index].classList.add('active');
    }

    function updateTrackInfo(videoId) {
        const trackInfo = {
            '9RJVuT9Y_2k': { title: 'Cyberpunk Synthwave Mix', artist: 'Various Artists' },
            'm3h8e8vCc-s': { title: 'Hacker Coding Music', artist: 'Programming Mix' },
            'MVPTGNGiI-4': { title: 'Electronic Focus Music', artist: 'Deep Work Mix' }
        };

        const info = trackInfo[videoId];
        if (info) {
            const titleEl = document.querySelector('.track-title');
            const artistEl = document.querySelector('.track-artist');
            if (titleEl) titleEl.textContent = info.title;
            if (artistEl) artistEl.textContent = info.artist;
        }
    }
}

// Contact form with validation
function initializeContactForm() {
    const contactForm = document.getElementById && document.getElementById('contact-form');
    const formFeedback = document.getElementById && document.getElementById('form-feedback');

    if (!contactForm || !formFeedback) return;

    contactForm.addEventListener('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(contactForm);
        const name = (formData.get('name') || '').toString().trim();
        const email = (formData.get('email') || '').toString().trim();
        const subject = (formData.get('subject') || '').toString().trim();
        const message = (formData.get('message') || '').toString().trim();

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

// Intro Sequence and main initialization
document.addEventListener('DOMContentLoaded', function() {
    try {
        const introSequence = document.getElementById('intro-sequence');
        if (introSequence) {
            setTimeout(() => {
                introSequence.style.display = 'none';
                initializeParticles();
            }, 5000);
        } else {
            // If no intro, initialize particles immediately
            initializeParticles();
        }

        // Initialize components (guarded inside their functions)
        initializeMusicPlayer();
        initializeContactForm();

        // Intersection Observer for sections
        const observerOptions = { threshold: 0.1, rootMargin: '0px 0px -100px 0px' };
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    animateTimelineItems();
                }
            });
        }, observerOptions);

        (document.querySelectorAll('.section') || []).forEach(section => {
            try { observer.observe(section); } catch (e) {}
        });

        // Navigation with keyboard support
        const navItems = document.querySelectorAll('.nav-item') || [];
        const sections = document.querySelectorAll('.section') || [];

        navItems.forEach(item => {
            item.addEventListener('click', function() { navigateToSection(this); });

            item.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    navigateToSection(this);
                }
            });
        });

        function navigateToSection(navItem) {
            if (!navItem) return;

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
            const targetSection = sectionId ? document.getElementById(sectionId) : null;
            if (!targetSection) return;
            targetSection.style.display = 'block';
            setTimeout(() => {
                targetSection.classList.add('visible');
            }, 10);

            // Scroll to section
            targetSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        // Dynamic gradient based on mouse movement
        const gradient = document.querySelector('.cyber-gradient');
        if (gradient) {
            document.addEventListener('mousemove', (e) => {
                const x = e.clientX / window.innerWidth;
                const y = e.clientY / window.innerHeight;
                gradient.style.background =
                    `linear-gradient(${135 + x * 45}deg, rgba(0, 247, 255, 0.05) 0%, transparent 50%),` +
                    `linear-gradient(${-135 + y * 45}deg, rgba(255, 0, 247, 0.05) 0%, transparent 50%)`;
            });
        }

        // Parallax effect for floating elements
        document.addEventListener('mousemove', (e) => {
            const floatingElements = document.querySelectorAll('.floating-element') || [];
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;

            floatingElements.forEach((element, index) => {
                try {
                    const speed = (index + 1) * 0.05;
                    const x = (mouseX - 0.5) * 100 * speed;
                    const y = (mouseY - 0.5) * 100 * speed;
                    element.style.transform = `translate(${x}px, ${y}px)`;
                } catch (err) { /* ignore per-element errors */ }
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
            whoami: { execute: () => 'Roman Orłowski - Cybersecurity Expert | 15+ years experience in IT & Security' },
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
            nmap: { execute: () => `Starting Nmap 7.92 scan...
Scanning target 192.168.1.1...
Discovered open port 80/tcp on target
Discovered open port 443/tcp on target
Discovered open port 22/tcp on target
Nmap scan report complete.` },
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
                    if (terminalOutput) terminalOutput.innerHTML = '<div class="terminal-line">Terminal cleared.</div>';
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
                    if (terminalOutput) terminalOutput.appendChild(commandLine);

                    // Execute command
                    let result;
                    if (commands[command]) {
                        result = commands[command].execute();
                    } else {
                        result = `Command not found: ${command}\nType 'help' for available commands`;
                    }

                    // Display result
                    if (result && terminalOutput) {
                        const resultElement = document.createElement('div');
                        resultElement.className = 'terminal-line';
                        resultElement.style.whiteSpace = 'pre-wrap';
                        resultElement.textContent = result;
                        terminalOutput.appendChild(resultElement);
                    }

                    // Scroll to bottom
                    if (terminalOutput) terminalOutput.scrollTop = terminalOutput.scrollHeight;
                }
            });
        }

        // Quiz Functionality with keyboard support
        const quizOptions = document.querySelectorAll('.quiz-option') || [];
        quizOptions.forEach(option => {
            option.addEventListener('click', function() { handleQuizAnswer(this); });

            option.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    handleQuizAnswer(this);
                }
            });
        });

        function handleQuizAnswer(selectedOption) {
            if (!selectedOption) return;
            const question = selectedOption.closest && selectedOption.closest('.quiz-question');
            if (!question) return;
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
                if (feedback) {
                    feedback.textContent = '✓ Correct! Great job!';
                    feedback.className = 'quiz-feedback correct';
                }
            } else {
                selectedOption.style.background = 'rgba(255, 85, 85, 0.2)';
                selectedOption.style.borderColor = 'var(--critical)';
                if (feedback) {
                    feedback.textContent = '✗ Incorrect. Try again!';
                    feedback.className = 'quiz-feedback incorrect';
                }
            }
        }

        // Smooth scroll for anchor links
        (document.querySelectorAll('a[href^="#"]') || []).forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        // Add typing effect to header
        const headerText = document.querySelector('.header h1');
        if (headerText) {
            const letters = headerText.querySelectorAll('.letter') || [];
            letters.forEach((letter, index) => {
                letter.style.animationDelay = `${index * 0.1}s`;
            });
        }

        // Timeline animation
        function animateTimelineItems() {
            const timelineItems = document.querySelectorAll('.timeline-item') || [];
            timelineItems.forEach((item, index) => {
                setTimeout(() => {
                    try {
                        item.style.animationDelay = `${index * 0.1}s`;
                        item.style.animation = 'slideInRight 0.5s forwards';
                    } catch (e) {}
                }, 100);
            });
        }

        // Initialize timeline animation
        animateTimelineItems();

        // Keyword hover effects
        (document.querySelectorAll('.keyword') || []).forEach(keyword => {
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
        (document.querySelectorAll('.hobby-item') || []).forEach((item, index) => {
            item.style.animationDelay = `${index * 0.1}s`;
            item.style.animation = 'fadeInUp 0.5s forwards';
        });

        // Skill card hover effects
        (document.querySelectorAll('.skill-card, .cert-card, .tool-card, .education-card') || []).forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-5px) scale(1.02)';
            });

            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0) scale(1)';
            });
        });

        // Matrix cell interactions
        (document.querySelectorAll('.matrix-cell') || []).forEach(cell => {
            cell.addEventListener('mouseenter', function() {
                this.style.transform = 'scale(1.05)';
            });

            cell.addEventListener('mouseleave', function() {
                this.style.transform = 'scale(1)';
            });
        });

        // Add glow effect to buttons on hover
        (document.querySelectorAll('.cyber-button') || []).forEach(button => {
            button.addEventListener('mouseenter', function() {
                this.style.boxShadow = '0 10px 30px rgba(0, 247, 255, 0.4)';
            });

            button.addEventListener('mouseleave', function() {
                this.style.boxShadow = '0 4px 15px rgba(0, 247, 255, 0.2)';
            });
        });

        // Random keyword glitch effect
        setInterval(() => {
            const keywordsList = document.querySelectorAll('.keyword') || [];
            if (keywordsList.length > 0 && Math.random() > 0.9) {
                const randomKeyword = keywordsList[Math.floor(Math.random() * keywordsList.length)];
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
                try {
                    navigator.serviceWorker.register('sw.js').catch(err => {
                        console.log('Service Worker registration failed:', err);
                    });
                } catch (e) {
                    console.warn('Service worker registration error:', e);
                }
            });
        }
    } catch (err) {
        console.warn('DOMContentLoaded initialization failed:', err);
    }
});

// Keyboard shortcuts (global)
document.addEventListener('keydown', function(e) {
    try {
        // Ctrl + K to focus terminal
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            const terminalCommand = document.getElementById('terminal-command');
            if (terminalCommand) {
                terminalCommand.focus();
                const terminalEl = document.getElementById('terminal');
                if (terminalEl) terminalEl.scrollIntoView({ behavior: 'smooth' });
            }
        }

        // Space to toggle music player (only when not typing)
        if (e.key === ' ' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
            e.preventDefault();
            const playBtn = document.getElementById('play-btn');
            if (playBtn) playBtn.click();
        }

        // Escape to clear terminal input
        if (e.key === 'Escape') {
            const terminalCommand = document.getElementById('terminal-command');
            if (terminalCommand && document.activeElement === terminalCommand) {
                terminalCommand.value = '';
            }
        }
    } catch (err) {
        // ignore
    }
});

// Handle unified attributes navigation (guarded)
document.addEventListener('DOMContentLoaded', function() {
    try {
        const navItems = document.querySelectorAll('.nav-item') || [];

        navItems.forEach(item => {
            item.addEventListener('click', function() {
                const sectionId = this.getAttribute('data-section');

                // If clicking on abilities or management, show the personality section (unified)
                if (sectionId === 'abilities' || sectionId === 'management') {
                    const personalityNav = document.querySelector('.nav-item[data-section="personality"]');
                    if (personalityNav) personalityNav.click();
                }
            });
        });
    } catch (e) { /* ignore */ }
});

// Error handling for failed resources
window.addEventListener('error', function(e) {
    try {
        const source = e && (e.filename || (e.target && e.target.src));
        console.warn('Resource failed to load:', source);

        // Fallback for failed YouTube embed
        if (e && e.target && e.target.tagName === 'IFRAME' && e.target.src && e.target.src.includes('youtube')) {
            const musicPlayer = document.querySelector('.music-player');
            if (musicPlayer) {
                musicPlayer.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--primary);">Music player unavailable</div>';
            }
        }
    } catch (err) { /* ignore */ }
}, true);

// Music Player - slide out from edge (guarded)
(function() {
    const musicPlayer = document.getElementById && document.getElementById('music-player');
    const playerHeader = document.getElementById && document.getElementById('player-header');
    let playerCollapsed = true;

    if (!musicPlayer || !playerHeader) return;

    try {
        // Initialize player position
        musicPlayer.style.transform = 'translateX(calc(100% - 40px))';
        musicPlayer.classList.add('slide-player');

        playerHeader.addEventListener('mouseenter', function() {
            if (playerCollapsed) {
                musicPlayer.style.transform = 'translateX(0)';
                playerCollapsed = false;
            }
        });

        musicPlayer.addEventListener('mouseleave', function() {
            if (!playerCollapsed && !isPlaying) {
                setTimeout(() => {
                    musicPlayer.style.transform = 'translateX(calc(100% - 40px))';
                    playerCollapsed = true;
                }, 500);
            }
        });
    } catch (e) {
        console.warn('Music player slide error:', e);
    }
})();

// Terminology links functionality
const terminologyLinks = {
    'NIST': 'https://www.nist.gov/cyberframework',
    'ISO 27001': 'https://www.iso.org/isoiec-27001-information-security.html',
    'NIS2': 'https://digital-strategy.ec.europa.eu/en/policies/nis2-directive',
    'SOX': 'https://www.soxlaw.com/',
    'GDPR': 'https://gdpr.eu/',
    'DORA': 'https://www.esma.europa.eu/policy-rules/mifid-ii-and-mifir',
    'CISSP': 'https://www.isc2.org/Certifications/CISSP',
    'CISM': 'https://www.isaca.org/credentialing/cism',
    'CISA': 'https://www.isaca.org/credentialing/cisa',
    'GSLC': 'https://www.giac.org/certifications/security-leadership-certification-gslc/',
    'GSTRT': 'https://www.giac.org/certifications/strategic-planning-policy-leadership-gstrt/',
    'GCPM': 'https://www.giac.org/certifications/project-management-certification-gcpm/',
    'IAM': 'https://en.wikipedia.org/wiki/Identity_and_access_management',
    'PAM': 'https://en.wikipedia.org/wiki/Privileged_access_management',
    'TOMs': 'https://en.wikipedia.org/wiki/Target_operating_model',
    'RACI': 'https://en.wikipedia.org/wiki/Responsibility_assignment_matrix',
    'CTI': 'https://en.wikipedia.org/wiki/Threat_intelligence'
};

// Add links to terminology (callable)
function addTerminologyLinks() {
    try {
        const keywords = document.querySelectorAll('.keyword') || [];
        keywords.forEach(keyword => {
            try {
                const term = (keyword.textContent || '').trim();
                if (terminologyLinks[term]) {
                    keyword.style.cursor = 'pointer';
                    keyword.style.textDecoration = 'underline';
                    keyword.style.textDecorationStyle = 'dotted';

                    keyword.addEventListener('click', function(e) {
                        e.preventDefault();
                        window.open(terminologyLinks[term], '_blank', 'noopener,noreferrer');
                    });

                    // Add tooltip
                    keyword.setAttribute('title', `Click to learn more about ${term}`);

                    // Add hover effect
                    keyword.addEventListener('mouseenter', function() {
                        this.style.textDecoration = 'underline';
                        this.style.textDecorationStyle = 'solid';
                        this.style.textDecorationColor = 'var(--primary)';
                    });

                    keyword.addEventListener('mouseleave', function() {
                        this.style.textDecoration = 'underline';
                        this.style.textDecorationStyle = 'dotted';
                    });
                }
            } catch (err) { /* ignore per-keyword errors */ }
        });
    } catch (e) { /* ignore */ }
}

// SOC Dashboard effects
function initializeSOCEffects() {
    try {
        // Add scanning line effect
        const scanline = document.createElement('div');
        scanline.className = 'scanline-effect';
        document.body.appendChild(scanline);

        // Add data stream effect
        const dataStream = document.createElement('div');
        dataStream.className = 'data-stream';
        document.body.appendChild(dataStream);

        // Add threat level indicator
        const threatIndicator = document.createElement('div');
        threatIndicator.className = 'threat-indicator';
        threatIndicator.innerHTML = `
            <div class="threat-level">
                <span class="threat-label">THREAT LEVEL:</span>
                <span class="threat-status">LOW</span>
            </div>
            <div class="threat-bar">
                <div class="threat-fill"></div>
            </div>
        `;
        const headerEl = document.querySelector('.header');
        if (headerEl) headerEl.appendChild(threatIndicator);

        // Animate threat level
        setInterval(() => {
            const threatLevel = Math.random() * 100;
            const threatFill = document.querySelector('.threat-fill');
            const threatStatus = document.querySelector('.threat-status');

            if (threatFill) threatFill.style.width = threatLevel + '%';

            if (threatStatus) {
                if (threatLevel < 30) {
                    threatStatus.textContent = 'LOW';
                    threatStatus.style.color = 'var(--low)';
                } else if (threatLevel < 70) {
                    threatStatus.textContent = 'MEDIUM';
                    threatStatus.style.color = 'var(--medium)';
                } else {
                    threatStatus.textContent = 'HIGH';
                    threatStatus.style.color = 'var(--critical)';
                }
            }
        }, 3000);
    } catch (e) {
        console.warn('initializeSOCEffects error:', e);
    }
}

// Enhanced mouse effects
function initializeMouseEffects() {
    try {
        // Add cursor trail effect
        const cursorTrail = document.createElement('div');
        cursorTrail.className = 'cursor-trail';
        document.body.appendChild(cursorTrail);

        let mouseX = 0, mouseY = 0;
        let trailX = 0, trailY = 0;

        document.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
        });

        function animateTrail() {
            trailX += (mouseX - trailX) * 0.1;
            trailY += (mouseY - trailY) * 0.1;

            cursorTrail.style.left = trailX + 'px';
            cursorTrail.style.top = trailY + 'px';

            requestAnimationFrame(animateTrail);
        }
        animateTrail();

        // Add grid interaction
        const gridOverlay = document.querySelector('.grid-overlay');
        if (gridOverlay) {
            document.addEventListener('mousemove', (e) => {
                const x = (e.clientX / window.innerWidth) * 100;
                const y = (e.clientY / window.innerHeight) * 100;

                gridOverlay.style.background = `
                    linear-gradient(90deg, transparent ${x-1}%, rgba(0,247,255,0.1) ${x}%, transparent ${x+1}%),
                    linear-gradient(180deg, transparent ${y-1}%, rgba(0,247,255,0.1) ${y}%, transparent ${y+1}%)
                `;
            });
        }
    } catch (e) {
        console.warn('initializeMouseEffects error:', e);
    }
}

// Dashboard widget effects
function initializeDashboardWidgets() {
    try {
        const container = document.querySelector('.container');
        const mainEl = document.querySelector('main');
        if (!container) return;

        // Add system status widgets
        const statusWidgets = document.createElement('div');
        statusWidgets.className = 'status-widgets';
        statusWidgets.innerHTML = `
            <div class="widget">
                <div class="widget-title">SYSTEM STATUS</div>
                <div class="widget-content">
                    <div class="status-item">
                        <span class="status-label">CPU:</span>
                        <span class="status-value" id="cpu-usage">45%</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">MEMORY:</span>
                        <span class="status-value" id="memory-usage">67%</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">NETWORK:</span>
                        <span class="status-value" id="network-usage">23%</span>
                    </div>
                </div>
            </div>
            <div class="widget">
                <div class="widget-title">ACTIVE ALERTS</div>
                <div class="widget-content">
                    <div class="alert-item">
                        <span class="alert-severity low">●</span>
                        <span class="alert-text">Firewall update available</span>
                    </div>
                    <div class="alert-item">
                        <span class="alert-severity medium">●</span>
                        <span class="alert-text">Unusual login activity</span>
                    </div>
                </div>
            </div>
        `;

        container.insertBefore(statusWidgets, mainEl || null);

        // Animate status values
        setInterval(() => {
            const cpuEl = document.getElementById('cpu-usage');
            const memEl = document.getElementById('memory-usage');
            const netEl = document.getElementById('network-usage');

            if (cpuEl) cpuEl.textContent = Math.floor(Math.random() * 30 + 30) + '%';
            if (memEl) memEl.textContent = Math.floor(Math.random() * 20 + 50) + '%';
            if (netEl) netEl.textContent = Math.floor(Math.random() * 40 + 10) + '%';
        }, 2000);
    } catch (e) {
        console.warn('initializeDashboardWidgets error:', e);
    }
}

// Education section 3-column layout
function initializeEducationLayout() {
    try {
        const educationSection = document.querySelector('#education');
        if (!educationSection) return;

        educationSection.innerHTML = `
            <h2><i class="fas fa-graduation-cap"></i> Education & Languages</h2>
            <div class="education-dashboard">
                <div class="edu-column">
                    <div class="edu-card">
                        <h3><i class="fas fa-school"></i> Education</h3>
                        <div class="edu-content">
                            <p><strong>Diploma High School</strong><br>Kraków</p>
                            <h4>Licenses & Certifications:</h4>
                            <ul class="cert-list">
                                <li><i class="fas fa-certificate"></i> SEP authorization for supervision and operation up to 1 kV</li>
                                <li><i class="fas fa-certificate"></i> MDF Accreditation License (Frame Basic)</li>
                                <li><i class="fas fa-certificate"></i> Crane Operations Basic Slinging Course</li>
                                <li><i class="fas fa-certificate"></i> Driving License category D</li>
                                <li><i class="fas fa-certificate"></i> Professional Customer Phone Support</li>
                                <li><i class="fas fa-certificate"></i> Counterintelligence Awareness and Reporting Course</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="edu-column">
                    <div class="edu-card">
                        <h3><i class="fas fa-language"></i> Languages</h3>
                        <div class="language-dashboard">
                            <div class="lang-item">
                                <div class="lang-header">
                                    <span class="lang-name">Polish</span>
                                    <span class="lang-level-badge native">Native</span>
                                </div>
                                <div class="lang-progress">
                                    <div class="lang-progress-bar" style="width: 100%"></div>
                                </div>
                            </div>
                            <div class="lang-item">
                                <div class="lang-header">
                                    <span class="lang-name">English</span>
                                    <span class="lang-level-badge advanced">C1</span>
                                </div>
                                <div class="lang-progress">
                                    <div class="lang-progress-bar" style="width: 85%"></div>
                                </div>
                            </div>
                            <div class="lang-item">
                                <div class="lang-header">
                                    <span class="lang-name">German</span>
                                    <span class="lang-level-badge intermediate">B1</span>
                                </div>
                                <div class="lang-progress">
                                    <div class="lang-progress-bar" style="width: 60%"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="edu-column">
                    <div class="edu-card">
                        <h3><i class="fas fa-heart"></i> Hobbies & Interests</h3>
                        <div class="hobbies-dashboard">
                            <div class="hobby-card">
                                <i class="fas fa-fist-raised"></i>
                                <span>Mixed Martial Arts</span>
                                <div class="hobby-indicator active"></div>
                            </div>
                            <div class="hobby-card">
                                <i class="fas fa-basketball-ball"></i>
                                <span>Basketball</span>
                                <div class="hobby-indicator active"></div>
                            </div>
                            <div class="hobby-card">
                                <i class="fas fa-music"></i>
                                <span>Music Editing</span>
                                <div class="hobby-indicator"></div>
                            </div>
                            <div class="hobby-card">
                                <i class="fas fa-video"></i>
                                <span>Video Editing</span>
                                <div class="hobby-indicator active"></div>
                            </div>
                            <div class="hobby-card">
                                <i class="fas fa-book"></i>
                                <span>Reading Books</span>
                                <div class="hobby-indicator active"></div>
                            </div>
                            <div class="hobby-card">
                                <i class="fas fa-tools"></i>
                                <span>DIY Projects</span>
                                <div class="hobby-indicator"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    } catch (e) {
        console.warn('initializeEducationLayout error:', e);
    }
}

// Initialize all enhancements after main content load
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(() => {
        try {
            addTerminologyLinks();
            initializeSOCEffects();
            initializeMouseEffects();
            initializeDashboardWidgets();
            initializeEducationLayout();
        } catch (e) {
            console.warn('Post DOM initialization error:', e);
        }
    }, 1000);
});
