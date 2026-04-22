// ============================================
// DETECT MOBILE DEVICE
// ============================================
const isMobile = () => window.innerWidth <= 768;
const isTablet = () => window.innerWidth > 768 && window.innerWidth <= 1024;
const isDesktop = () => window.innerWidth > 1024;

// ============================================
// PARTICLES.JS CONFIGURATION - PEŁNA WERSJA
// ============================================
const particleConfig = (() => {
    if (isMobile()) {
        return {
            particles: {
                number: {
                    value: 35,
                    density: {
                        enable: true,
                        value_area: 1200
                    }
                },
                color: {
                    value: ['#ffff00', '#ff8800', '#dd00ff', '#00ff00', '#00f7ff']
                },
                shape: {
                    type: 'circle',
                    stroke: {
                        width: 0,
                        color: '#000000'
                    },
                    polygon: {
                        nb_sides: 5
                    }
                },
                opacity: {
                    value: 0.4,
                    random: true,
                    anim: {
                        enable: true,
                        speed: 1,
                        opacity_min: 0.1,
                        sync: false
                    }
                },
                size: {
                    value: 2,
                    random: true,
                    anim: {
                        enable: true,
                        speed: 2,
                        size_min: 0.5,
                        sync: false
                    }
                },
                line_linked: {
                    enable: true,
                    distance: 120,
                    color: '#ffff00',
                    opacity: 0.2,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 1.5,
                    direction: 'none',
                    random: true,
                    straight: false,
                    out_mode: 'out',
                    bounce: false,
                    attract: {
                        enable: false,
                        rotateX: 600,
                        rotateY: 1200
                    }
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
        };
    } else {
        return {
            particles: {
                number: {
                    value: 120,
                    density: {
                        enable: true,
                        value_area: 800
                    }
                },
                color: {
                    value: ['#ffff00', '#ff8800', '#dd00ff', '#00ff00', '#00f7ff', '#ff5555']
                },
                shape: {
                    type: 'circle',
                    stroke: {
                        width: 0,
                        color: '#000000'
                    },
                    polygon: {
                        nb_sides: 5
                    },
                    image: {
                        src: '',
                        width: 100,
                        height: 100
                    }
                },
                opacity: {
                    value: 0.6,
                    random: true,
                    anim: {
                        enable: true,
                        speed: 1.5,
                        opacity_min: 0.2,
                        sync: false
                    }
                },
                size: {
                    value: 3.5,
                    random: true,
                    anim: {
                        enable: true,
                        speed: 3,
                        size_min: 0.8,
                        sync: false
                    }
                },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: '#ffff00',
                    opacity: 0.4,
                    width: 1.5
                },
                move: {
                    enable: true,
                    speed: 2.5,
                    direction: 'none',
                    random: true,
                    straight: false,
                    out_mode: 'out',
                    bounce: false,
                    attract: {
                        enable: true,
                        rotateX: 600,
                        rotateY: 600
                    }
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
                        distance: 180,
                        line_linked: {
                            opacity: 0.8
                        }
                    },
                    bubble: {
                        distance: 200,
                        size: 6,
                        duration: 0.4
                    },
                    repulse: {
                        distance: 200,
                        duration: 0.4
                    },
                    push: {
                        particles_nb: 4
                    },
                    remove: {
                        particles_nb: 2
                    }
                }
            },
            retina_detect: true
        };
    }
})();

// Initialize particles.js
if (typeof particlesJS !== 'undefined') {
    particlesJS('particles-js', particleConfig);
    console.log('Particles.js initialized');
}

// ============================================
// YOUTUBE PLAYER INTEGRATION - PEŁNA WERSJA
// ============================================
let ytPlayer = null;
let isYtReady = false;
let currentVideoId = 'dQw4w9WgXcQ';
let ytVolume = 50;

function loadYouTubeAPI() {
    if (document.getElementById('youtube-api-script')) return;
    const tag = document.createElement('script');
    tag.id = 'youtube-api-script';
    tag.src = 'https://www.youtube.com/iframe_api';
    const firstScriptTag = document.getElementsByTagName('script')[0];
    firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);
}

function onYouTubeIframeAPIReady() {
    const playerDiv = document.getElementById('yt-player');
    if (!playerDiv) {
        console.error('YouTube player div not found');
        return;
    }
    
    ytPlayer = new YT.Player('yt-player', {
        height: '180',
        width: '100%',
        videoId: currentVideoId,
        playerVars: {
            'playsinline': 1,
            'controls': 0,
            'disablekb': 1,
            'modestbranding': 1,
            'rel': 0,
            'showinfo': 0,
            'autoplay': 0,
            'loop': 0,
            'fs': 0
        },
        events: {
            'onReady': onPlayerReady,
            'onStateChange': onPlayerStateChange,
            'onError': onPlayerError
        }
    });
}

function onPlayerReady(event) {
    isYtReady = true;
    ytPlayer.setVolume(ytVolume);
    console.log('YouTube Player ready');
    updateTrackInfo('Ready to play');
    
    // Load last played video from localStorage
    const lastVideo = localStorage.getItem('lastYouTubeVideo');
    if (lastVideo && lastVideo !== currentVideoId) {
        loadYouTubeVideo(lastVideo);
        const urlInput = document.getElementById('yt-url');
        if (urlInput) urlInput.value = lastVideo;
    }
}

function onPlayerStateChange(event) {
    const playBtn = document.getElementById('yt-play-btn');
    const pauseBtn = document.getElementById('yt-pause-btn');
    
    if (event.data === YT.PlayerState.PLAYING) {
        if (playBtn) playBtn.style.display = 'none';
        if (pauseBtn) pauseBtn.style.display = 'inline-flex';
        updateTrackInfo('Playing');
    } else if (event.data === YT.PlayerState.PAUSED) {
        if (playBtn) playBtn.style.display = 'inline-flex';
        if (pauseBtn) pauseBtn.style.display = 'none';
        updateTrackInfo('Paused');
    } else if (event.data === YT.PlayerState.ENDED) {
        if (playBtn) playBtn.style.display = 'inline-flex';
        if (pauseBtn) pauseBtn.style.display = 'none';
        updateTrackInfo('Finished');
    } else if (event.data === YT.PlayerState.BUFFERING) {
        updateTrackInfo('Buffering...');
    }
}

function onPlayerError(event) {
    console.error('YouTube Player Error:', event.data);
    updateTrackInfo('Error loading video');
    
    let errorMessage = '';
    switch(event.data) {
        case 2: errorMessage = 'Invalid video ID'; break;
        case 5: errorMessage = 'HTML5 player error'; break;
        case 100: errorMessage = 'Video not found'; break;
        case 101: errorMessage = 'Embedding disabled'; break;
        case 150: errorMessage = 'Embedding disabled'; break;
        default: errorMessage = 'Unknown error';
    }
    updateTrackInfo(`Error: ${errorMessage}`);
}

function updateTrackInfo(message) {
    const trackSpan = document.getElementById('current-track');
    if (trackSpan) {
        trackSpan.innerHTML = `<i class="fas fa-music"></i> ${message}`;
    }
}

function extractVideoId(input) {
    if (!input) return null;
    
    const patterns = [
        /(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})/,
        /^([a-zA-Z0-9_-]{11})$/
    ];
    
    for (const pattern of patterns) {
        const match = input.match(pattern);
        if (match && match[1]) {
            return match[1];
        }
    }
    return null;
}

function loadYouTubeVideo(input) {
    if (!ytPlayer || !isYtReady) {
        console.log('Player not ready, loading queued');
        setTimeout(() => loadYouTubeVideo(input), 500);
        return;
    }
    
    const videoId = extractVideoId(input);
    if (!videoId) {
        alert('Nieprawidłowy link YouTube. Użyj formatu:\nhttps://www.youtube.com/watch?v=XXXXXXXXXXX');
        return;
    }
    
    currentVideoId = videoId;
    ytPlayer.loadVideoById(videoId);
    localStorage.setItem('lastYouTubeVideo', videoId);
    updateTrackInfo(`Loading: ${videoId}`);
    
    // Update URL input
    const urlInput = document.getElementById('yt-url');
    if (urlInput) urlInput.value = videoId;
}

function playYouTube() {
    if (ytPlayer && isYtReady) {
        ytPlayer.playVideo();
    }
}

function pauseYouTube() {
    if (ytPlayer && isYtReady) {
        ytPlayer.pauseVideo();
    }
}

function stopYouTube() {
    if (ytPlayer && isYtReady) {
        ytPlayer.stopVideo();
        ytPlayer.seekTo(0);
        updateTrackInfo('Stopped');
    }
}

function toggleMuteYouTube() {
    if (!ytPlayer || !isYtReady) return;
    
    const muteBtn = document.getElementById('yt-mute-btn');
    if (ytPlayer.isMuted()) {
        ytPlayer.unMute();
        if (muteBtn) muteBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
        ytVolume = ytPlayer.getVolume();
    } else {
        ytPlayer.mute();
        if (muteBtn) muteBtn.innerHTML = '<i class="fas fa-volume-mute"></i>';
    }
}

function setYouTubeVolume(value) {
    if (ytPlayer && isYtReady) {
        ytVolume = Math.min(100, Math.max(0, value));
        ytPlayer.setVolume(ytVolume);
    }
}

// ============================================
// PIP-BOY TERMINAL COMMANDS - ROZBUDOWANE
// ============================================
const pipCommands = {
    help: () => {
        return `=== PIP-BOY OS COMMANDS ===
help           - Show this help
whoami         - Display system info
skills         - List loaded modules
verify [code]  - Verify candidate code
clear          - Clear terminal
date           - Show system time
status         - Show security status
scan           - Run network scan
report         - Show weekly report
version        - Show OS version
uptime         - Show system uptime
reboot         - Reboot terminal
theme [color]  - Change terminal theme
credits        - Show credits`;
    },
    
    whoami: () => {
        return `ROCyber_Security_System v2.0.1
User: Administrator
Role: Security Operations
Access Level: FULL
Session ID: ${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
    },
    
    skills: () => {
        return `=== LOADED MODULES ===
[ACTIVE] Threat Detection Engine v3.2
[ACTIVE] SIEM Integration Module
[ACTIVE] Zero Trust Enforcement
[ACTIVE] Compliance Scanner
[STANDBY] Incident Response
[STANDBY] Forensic Analyzer
[STANDBY] Malware Scanner`;
    },
    
    verify: (code) => {
        const storedCode = localStorage.getItem('verificationCode') || 'CYBER-2024-TRUST';
        if (!code) {
            return `VERIFICATION REQUIRED
Type: verify [code]
Contact your recruiter for the code.`;
        }
        if (code.toUpperCase() === storedCode) {
            return `✓ ACCESS GRANTED ✓
Welcome, verified candidate.
You have passed the security verification.
Proceed with the interview.`;
        }
        return `✗ ACCESS DENIED ✗
Invalid verification code.
Please contact your recruiter.`;
    },
    
    clear: () => {
        const output = document.getElementById('pipTerminalOutput');
        if (output) {
            output.innerHTML = '<div class="terminal-line">> Terminal cleared. Type "help" for commands.</div>';
        }
        return '';
    },
    
    date: () => {
        const now = new Date();
        return `System Time: ${now.toLocaleDateString()} ${now.toLocaleTimeString()}
Timezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}
Timestamp: ${now.getTime()}`;
    },
    
    status: () => {
        return `=== SECURITY STATUS ===
System Status: ACTIVE
Threat Level: LOW
Last Scan: ${new Date().toLocaleDateString()}
Firewall: ENABLED
IDS/IPS: ACTIVE
Encryption: AES-256
Compliance: 100%`;
    },
    
    scan: () => {
        return `[SCAN INITIATED]
Scanning network segments...
[OK] 192.168.1.0/24 - No threats
[OK] 10.0.0.0/8 - No threats
[OK] External perimeter - No threats
[WARN] 3 outdated signatures found
[INFO] Update recommended
Scan completed. System secure.`;
    },
    
    report: () => {
        return `=== WEEKLY SECURITY REPORT ===
Period: ${new Date(new Date().setDate(new Date().getDate() - 7)).toLocaleDateString()} - ${new Date().toLocaleDateString()}
Incidents: 0
Threats Blocked: 147
Patches Applied: 3
Compliance Score: 100%
Recommendations: None`;
    },
    
    version: () => {
        return `PIP-BOY OS v2.0.1 (Build 2024.001)
Kernel: ROCyber Secure Core 5.4
UI Version: Neon Genesis
API Version: 3.2.0`;
    },
    
    uptime: () => {
        const uptime = Math.floor(Date.now() / 1000);
        const days = Math.floor(uptime / 86400);
        const hours = Math.floor((uptime % 86400) / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);
        return `System Uptime: ${days}d ${hours}h ${minutes}m
Last Reboot: ${new Date().toLocaleString()}`;
    },
    
    reboot: () => {
        setTimeout(() => {
            const output = document.getElementById('pipTerminalOutput');
            if (output) {
                output.innerHTML = '<div class="terminal-line">> System rebooting...</div>';
                setTimeout(() => {
                    output.innerHTML = '<div class="terminal-line">> Terminal ready. Type "help" for commands.</div>';
                }, 1000);
            }
        }, 100);
        return 'Rebooting terminal...';
    },
    
    theme: (color) => {
        const colors = ['green', 'yellow', 'orange', 'purple', 'cyan'];
        if (color && colors.includes(color.toLowerCase())) {
            const terminal = document.querySelector('.pip-terminal');
            if (terminal) {
                terminal.style.borderColor = `var(--neon-${color})`;
            }
            return `Theme changed to: ${color}`;
        }
        return `Available themes: ${colors.join(', ')}`;
    },
    
    credits: () => {
        return `=== ROCYBER SOLUTIONS ===
Security System designed by Roman Orłowski
Powered by Advanced Threat Intelligence
© 2024 All Rights Reserved
www.rocybersolutions.com`;
    }
};

// ============================================
// MAIN TERMINAL COMMANDS - ROZBUDOWANE
// ============================================
const mainCommands = {
    help: () => {
        return `=== ROCYBER TERMINAL v2.0 ===
Available commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
help           - Show this help
whoami         - Display user info
skills         - List cybersecurity skills
nmap           - Run network scan simulation
msfconsole     - Launch Metasploit console
searchsploit   - Search exploit database
ceh_phases     - Show CEH hacking phases
privacy_tip    - Get privacy protection tip
disclosure     - Responsible disclosure info
analyze_log    - Analyze security log
decrypt_hash   - Hash decryption tool
check_vuln     - Check vulnerability DB
owasp_top10    - Display OWASP Top 10
azure_security - Azure best practices
incident_response - IR procedures
threat_hunt    - Threat hunting techniques
malware_analysis - Malware analysis workflow
forensics      - Digital forensics guide
compliance_check - Compliance frameworks
clear          - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type any command to execute`;
    },
    
    whoami: () => {
        return `Name: Roman Orłowski
Role: Cybersecurity Expert & Founder
Company: ROCyber Solutions
Experience: 15+ years
Certifications: CEH, Azure Security, ISO 27001, CCSP
Specialization: Cloud Security, Threat Detection, Zero Trust`;
    },
    
    skills: () => {
        return `=== CORE CYBERSECURITY SKILLS ===
┌─────────────────────────────────────────┐
│ Cloud Security                          │
│   • Azure Security Center               │
│   • AWS Shield                          │
│   • GCP Security Command Center         │
│   • Container Security (K8s)            │
│   • Zero Trust Architecture             │
├─────────────────────────────────────────┤
│ Threat Detection & Response             │
│   • SIEM (Splunk, QRadar, Sentinel)     │
│   • IDS/IPS                             │
│   • EDR                                 │
│   • Threat Hunting                      │
│   • MITRE ATT&CK                        │
├─────────────────────────────────────────┤
│ Network Security                        │
│   • Firewall (Palo Alto, Fortinet)      │
│   • VPN                                 │
│   • NAC                                 │
│   • Micro-segmentation                  │
├─────────────────────────────────────────┤
│ Compliance & Risk                       │
│   • ISO 27001                           │
│   • GDPR                                │
│   • NIST CSF                            │
│   • PCI-DSS, SOX, DORA                  │
├─────────────────────────────────────────┤
│ Offensive Security                      │
│   • Penetration Testing                 │
│   • Red Teaming                         │
│   • Social Engineering                  │
│   • Exploit Development                 │
├─────────────────────────────────────────┤
│ Incident Response & Forensics           │
│   • IR Planning & Execution             │
│   • Malware Analysis                    │
│   • Digital Forensics                   │
│   • Log Analysis                        │
└─────────────────────────────────────────┘`;
    },
    
    nmap: () => {
        return `[NMAP SCAN v7.92]
Starting Nmap at ${new Date().toLocaleTimeString()}
Initiating ARP Ping Scan at ...
Scanning 256 hosts [1 port/host]
Completed ARP Ping Scan at ... (0.5s)

Initiating Parallel DNS resolution of 256 hosts...
Completed Parallel DNS resolution (0.2s)

Initiating SYN Stealth Scan at ...
Scanning target 192.168.1.1 [1000 ports]
Discovered open port 22/tcp (SSH)
Discovered open port 80/tcp (HTTP)
Discovered open port 443/tcp (HTTPS)
Discovered open port 3306/tcp (MySQL)
Discovered open port 8080/tcp (HTTP-ALT)

Nmap scan report for target (192.168.1.1)
Host is up (0.0012s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
8080/tcp open  http-alt

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds

[RECOMMENDATION] Close unnecessary ports and implement firewall rules.`;
    },
    
    msfconsole: () => {
        return `[METASPLOIT FRAMEWORK v6.2.0]
========================================
       =[ metasploit v6.2.0-dev ]
+ -- --=[ 2298 exploits - 1189 auxiliary ]
+ -- --=[ 404 post modules - 602 payloads ]
+ -- --=[ 45 evasion modules ]

msf6 > use exploit/multi/http/example
msf6 exploit(multi/http/example) > set RHOSTS target.com
RHOSTS => target.com
msf6 exploit(multi/http/example) > set RPORT 80
RPORT => 80
msf6 exploit(multi/http/example) > check
[*] The target appears to be vulnerable.
msf6 exploit(multi/http/example) > exploit

[*] Started reverse TCP handler
[*] Sending exploit payload...
[*] Command shell session 1 opened

[WARNING] Use only with explicit authorization!
[ETHICS] Never attack systems without permission.`;
    },
    
    searchsploit: () => {
        return `[EXPLOIT DATABASE SEARCH]
========================================
Searching for: web application vulnerabilities

ID          | Title
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
50001 | WordPress Plugin XYZ 1.2 - RCE
50002 | Apache HTTP Server 2.4.x - Path Traversal
50003 | MySQL 8.x - Privilege Escalation
50004 | PHP 7.4.x - Code Injection
50005 | Nginx 1.18 - Buffer Overflow
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total results: 5

[NOTE] Always verify vulnerabilities before testing
[ETHICS] Responsible disclosure required`;
    },
    
    ceh_phases: () => {
        return `=== CEH ETHICAL HACKING PHASES ===
┌─────────────────────────────────────────────────┐
│ 1. RECONNAISSANCE (Footprinting)               │
│    • Passive information gathering             │
│    • OSINT techniques                          │
│    • Social engineering                        │
├─────────────────────────────────────────────────┤
│ 2. SCANNING & ENUMERATION                      │
│    • Network scanning (Nmap)                   │
│    • Port scanning                             │
│    • Service enumeration                       │
│    • Vulnerability scanning                    │
├─────────────────────────────────────────────────┤
│ 3. GAINING ACCESS (Exploitation)               │
│    • Exploiting vulnerabilities                │
│    • Password attacks                          │
│    • Social engineering                        │
│    • Web application attacks                   │
├─────────────────────────────────────────────────┤
│ 4. MAINTAINING ACCESS                          │
│    • Backdoors                                 │
│    • Rootkits                                  │
│    • Persistence mechanisms                    │
│    • Privilege escalation                      │
├─────────────────────────────────────────────────┤
│ 5. COVERING TRACKS                             │
│    • Log cleaning                              │
│    • Hiding files                              │
│    • Tunneling                                 │
│    • Anti-forensics                            │
└─────────────────────────────────────────────────┘

[ETHICS] Only perform with written authorization!
[LAW] Unauthorized hacking is illegal.`;
    },
    
    privacy_tip: () => {
        return `=== PRIVACY PROTECTION TIPS ===
┌─────────────────────────────────────────────────┐
│ 🔒 Use strong encryption                       │
│    • VPN for all connections                   │
│    • HTTPS everywhere                          │
│    • End-to-end encrypted messaging            │
├─────────────────────────────────────────────────┤
│ 🔑 Enable Multi-Factor Authentication          │
│    • Use authenticator apps (not SMS)          │
│    • Hardware keys (YubiKey) recommended       │
│    • Backup codes stored securely              │
├─────────────────────────────────────────────────┤
│ 📊 Minimize data collection                    │
│    • GDPR compliance by design                 │
│    • Data retention policies                   │
│    • Regular data purging                      │
├─────────────────────────────────────────────────┤
│ 🛡️ Use privacy-respecting tools               │
│    • Signal for messaging                      │
│    • ProtonMail for email                      │
│    • Tor Browser for anonymity                 │
│    • DuckDuckGo for search                     │
├─────────────────────────────────────────────────┤
│ 🧹 Regular privacy hygiene                     │
│    • Clear browsing data                       │
│    • Review app permissions                    │
│    • Opt out of data collection                │
│    • Use ad/tracker blockers                   │
└─────────────────────────────────────────────────┘`;
    },
    
    disclosure: () => {
        return `=== RESPONSIBLE DISCLOSURE BEST PRACTICES ===
┌─────────────────────────────────────────────────┐
│ 1. IDENTIFY                                     │
│    • Verify vulnerability                       │
│    • Document findings                         │
│    • Assess impact                             │
├─────────────────────────────────────────────────┤
│ 2. REPORT                                       │
│    • Contact vendor first                       │
│    • Use security@ email                       │
│    • Provide clear details                     │
│    • Include POC if possible                   │
├─────────────────────────────────────────────────┤
│ 3. COORDINATE                                   │
│    • Allow 90 days for fix                     │
│    • Agree on disclosure date                  │
│    • Work with vendor team                     │
│    • Request CVE assignment                    │
├─────────────────────────────────────────────────┤
│ 4. DISCLOSE                                     │
│    • Coordinate public release                 │
│    • Publish advisory                          │
│    • Credit researchers                        │
│    • Share IOCs                                │
├─────────────────────────────────────────────────┤
│ 5. FOLLOW UP                                    │
│    • Verify patch effectiveness                │
│    • Update documentation                      │
│    • Share lessons learned                     │
└─────────────────────────────────────────────────┘

[ETHICS] Never disclose before patch is ready
[LAW] Follow local regulations`;
    },
    
    analyze_log: () => {
        return `[SECURITY LOG ANALYSIS]
========================================
Log file: /var/log/security/audit.log
Analysis started: ${new Date().toLocaleString()}

=== SUSPICIOUS EVENTS ===
[2024-01-15 08:23:45] Failed login attempt from 192.168.1.100 (user: admin)
[2024-01-15 08:23:47] Failed login attempt from 192.168.1.100 (user: admin)
[2024-01-15 08:23:49] Failed login attempt from 192.168.1.100 (user: admin)
[2024-01-15 08:23:51] Account locked: admin (3 failed attempts)
[2024-01-15 09:15:22] Successful authentication from 10.0.0.25 (user: jdoe)
[2024-01-15 09:15:30] File access: /etc/shadow by user jdoe [SUSPICIOUS]
[2024-01-15 09:16:05] Outbound connection to unknown IP 45.33.22.11:4444

=== ANALYSIS SUMMARY ===
• Brute force attempt detected (source: 192.168.1.100)
• Unauthorized file access attempt
• Potential C2 beaconing detected
• Recommend: Block IP, investigate user jdoe, analyze outbound traffic

=== RECOMMENDATIONS ===
1. Block IP 192.168.1.100 at firewall
2. Disable user jdoe account pending investigation
3. Run full malware scan
4. Review outbound traffic logs
5. Enable additional monitoring

Analysis complete.`;
    },
    
    decrypt_hash: () => {
        return `[HASH DECRYPTION TOOL]
========================================
Supported algorithms: MD5, SHA1, SHA256, NTLM

Enter hash: 5d41402abc4b2a76b9719d911017c592
Hash type detected: MD5
Searching rainbow tables...
┌─────────────────────────────────────────────────┐
│ RESULT FOUND!                                   │
│ Plaintext: hello                                │
│ Algorithm: MD5                                  │
│ Confidence: 99.9%                              │
└─────────────────────────────────────────────────┘

⚠️ WARNING: MD5 is cryptographically broken
Recommend using SHA-256 or bcrypt for passwords

Try another hash? (type new hash or 'exit')`;
    },
    
    check_vuln: () => {
        return `[VULNERABILITY DATABASE CHECK]
========================================
Checking known CVEs against current stack...

┌─────────────────────────────────────────────────┐
│ CRITICAL VULNERABILITIES FOUND                 │
├─────────────────────────────────────────────────┤
│ CVE-2024-1234 | CVSS: 9.8 | CRITICAL           │
│ Description: Remote Code Execution              │
│ Affected: Apache HTTP Server 2.4.49-2.4.51     │
│ Fix: Update to version 2.4.52+                 │
├─────────────────────────────────────────────────┤
│ CVE-2024-5678 | CVSS: 7.5 | HIGH               │
│ Description: SQL Injection                      │
│ Affected: MySQL 8.0.0-8.0.28                   │
│ Fix: Update to version 8.0.29+                 │
├─────────────────────────────────────────────────┤
│ CVE-2024-9012 | CVSS: 6.1 | MEDIUM             │
│ Description: Cross-Site Scripting (XSS)         │
│ Affected: Multiple WordPress plugins            │
│ Fix: Update plugins or remove vulnerable code   │
└─────────────────────────────────────────────────┘

=== RECOMMENDATIONS ===
1. IMMEDIATE: Patch CVE-2024-1234 (Critical)
2. Schedule: Update MySQL to patched version
3. Review: WordPress plugin security

Total vulnerable assets: 3
Estimated remediation time: 4 hours

Would you like detailed remediation steps? (yes/no)`;
    },
    
    owasp_top10: () => {
        return `=== OWASP TOP 10 2021 ===
┌────┬────────────────────────────────────────────┐
│ #  │ RISK                                       │
├────┼────────────────────────────────────────────┤
│ A01│ Broken Access Control                      │
│    │ • Missing restrictions on authenticated    │
│    │   users                                    │
