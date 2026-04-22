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
│    │ • IDOR vulnerabilities                     │
├────┼────────────────────────────────────────────┤
│ A02│ Cryptographic Failures                     │
│    │ • Weak encryption algorithms               │
│    │ • Improper key management                  │
│    │ • Missing encryption                       │
├────┼────────────────────────────────────────────┤
│ A03│ Injection                                  │
│    │ • SQL Injection                            │
│    │ • NoSQL Injection                          │
│    │ • OS Command Injection                     │
├────┼────────────────────────────────────────────┤
│ A04│ Insecure Design                            │
│    │ • Missing security controls                │
│    │ • Flawed business logic                    │
├────┼────────────────────────────────────────────┤
│ A05│ Security Misconfiguration                  │
│    │ • Default configurations                   │
│    │ • Verbose error messages                   │
│    │ • Missing security headers                 │
├────┼────────────────────────────────────────────┤
│ A06│ Vulnerable and Outdated Components         │
│    │ • Unpatched software                       │
│    │ • End-of-life components                   │
├────┼────────────────────────────────────────────┤
│ A07│ Identification and Authentication Failures │
│    │ • Weak password policies                   │
│    │ • Missing MFA                              │
├────┼────────────────────────────────────────────┤
│ A08│ Software and Data Integrity Failures       │
│    │ • Insecure CI/CD pipelines                 │
│    │ • Unsigned updates                         │
├────┼────────────────────────────────────────────┤
│ A09│ Security Logging and Monitoring Failures   │
│    │ • Insufficient logging                     │
│    │ • No alerting                              │
├────┼────────────────────────────────────────────┤
│ A10│ Server-Side Request Forgery (SSRF)         │
│    │ • Internal network scanning                │
│    │ • Cloud metadata access                    │
└────┴────────────────────────────────────────────┘

[RESOURCES]
https://owasp.org/www-project-top-ten/`;
    },
    
    azure_security: () => {
        return `=== AZURE SECURITY BEST PRACTICES ===
┌─────────────────────────────────────────────────┐
│ 1. IDENTITY & ACCESS MANAGEMENT                │
│    • Enable Azure AD MFA for all users         │
│    • Implement Conditional Access policies     │
│    • Use Privileged Identity Management (PIM)  │
│    • Regular access reviews                    │
├─────────────────────────────────────────────────┤
│ 2. NETWORK SECURITY                            │
│    • Network Security Groups (NSGs)            │
│    • Azure Firewall                            │
│    • DDoS Protection                           │
│    • Web Application Firewall (WAF)            │
├─────────────────────────────────────────────────┤
│ 3. DATA PROTECTION                             │
│    • Azure Key Vault for secrets               │
│    • Encryption at rest (SSE)                  │
│    • Encryption in transit (TLS)               │
│    • Azure Information Protection              │
├─────────────────────────────────────────────────┤
│ 4. MONITORING & THREAT DETECTION               │
│    • Azure Sentinel SIEM                       │
│    • Azure Security Center                     │
│    • Defender for Cloud                        │
│    • Log Analytics Workspaces                  │
├─────────────────────────────────────────────────┤
│ 5. COMPLIANCE & GOVERNANCE                     │
│    • Azure Policy                              │
│    • Azure Blueprints                          │
│    • Compliance Manager                        │
│    • Regulatory compliance reports             │
└─────────────────────────────────────────────────┘

[CHECKLIST] Regular security assessments required
[AUDIT] Enable diagnostic logging for all resources`;
    },
    
    incident_response: () => {
        return `=== INCIDENT RESPONSE PROCEDURES ===
┌─────────────────────────────────────────────────┐
│ PHASE 1: PREPARATION                           │
│    • Establish IR team                         │
│    • Define roles & responsibilities           │
│    • Create playbooks                          │
│    • Acquire tools & training                  │
├─────────────────────────────────────────────────┤
│ PHASE 2: DETECTION & ANALYSIS                  │
│    • Monitor alerts                            │
│    • Investigate anomalies                     │
│    • Determine scope & impact                  │
│    • Preserve evidence                         │
├─────────────────────────────────────────────────┤
│ PHASE 3: CONTAINMENT                           │
│    • Short-term containment (isolate)          │
│    • Long-term containment (patching)          │
│    • Backup critical data                      │
├─────────────────────────────────────────────────┤
│ PHASE 4: ERADICATION                           │
│    • Remove malware                            │
│    • Close attack vectors                      │
│    • Reset compromised credentials             │
│    • Apply security patches                    │
├─────────────────────────────────────────────────┤
│ PHASE 5: RECOVERY                              │
│    • Restore from clean backups                │
│    • Monitor for re-infection                  │
│    • Gradual service restoration               │
├─────────────────────────────────────────────────┤
│ PHASE 6: POST-INCIDENT                         │
│    • Lessons learned meeting                   │
│    • Update procedures                         │
│    • Legal & regulatory reporting              │
│    • Improve security controls                 │
└─────────────────────────────────────────────────┘

[TIMELINE] Response within 24 hours required
[ESCALATION] Notify management immediately for critical incidents`;
    },
    
    threat_hunt: () => {
        return `=== THREAT HUNTING TECHNIQUES ===
┌─────────────────────────────────────────────────┐
│ NETWORK ANALYSIS                               │
│    • Wireshark packet inspection               │
│    • Zeek (Bro) network monitoring             │
│    • NetFlow analysis                          │
│    • DNS tunneling detection                   │
├─────────────────────────────────────────────────┤
│ ENDPOINT ANALYSIS                              │
│    • Sysmon logs review                        │
│    • Windows Event Viewer                      │
│    • Process tree analysis                     │
│    • Registry changes                          │
├─────────────────────────────────────────────────┤
│ LATERAL MOVEMENT DETECTION                     │
│    • RDP/SSH logs                              │
│    • PSExec usage                              │
│    • Scheduled tasks                           │
│    • WMI activity                              │
├─────────────────────────────────────────────────┤
│ C2 COMMUNICATION PATTERNS                      │
│    • Beaconing detection                       │
│    • Domain generation algorithm (DGA)         │
│    • Encrypted traffic analysis                │
│    • Unusual port usage                        │
├─────────────────────────────────────────────────┤
│ USER BEHAVIOR ANALYTICS                        │
│    • Impossible travel                         │
│    • Unusual login times                       │
│    • Data exfiltration patterns                │
│    • Privilege escalation attempts             │
└─────────────────────────────────────────────────┘

[FRAMEWORK] MITRE ATT&CK mapping recommended
[TOOLS] Use SIEM with UEBA capabilities`;
    },
    
    malware_analysis: () => {
        return `=== MALWARE ANALYSIS WORKFLOW ===
┌─────────────────────────────────────────────────┐
│ 1. STATIC ANALYSIS                             │
│    • File properties (hash, size, type)        │
│    • String extraction (strings command)       │
│    • PE/ELF header analysis                    │
│    • Import/export table review                │
│    • Disassembly (IDA Pro, Ghidra)             │
├─────────────────────────────────────────────────┤
│ 2. DYNAMIC ANALYSIS                            │
│    • Sandbox execution (Cuckoo, CAPE)          │
│    • API monitoring                            │
│    • Registry/File system changes              │
│    • Process behavior analysis                 │
├─────────────────────────────────────────────────┤
│ 3. NETWORK ANALYSIS                            │
│    • Traffic capture (Wireshark)               │
│    • DNS queries                               │
│    • HTTP/HTTPS requests                       │
│    • C2 communication patterns                 │
├─────────────────────────────────────────────────┤
│ 4. CODE ANALYSIS                               │
│    • Reverse engineering                       │
│    • Decompilation                             │
│    • Debugging (x64dbg, OllyDbg)               │
│    • Anti-analysis bypass                      │
├─────────────────────────────────────────────────┤
│ 5. REPORTING                                   │
│    • Indicators of Compromise (IOCs)           │
│    • YARA rules                                │
│    • Mitigation recommendations                │
│    • Family classification                     │
└─────────────────────────────────────────────────┘

[TOOLS] Ghidra, IDA Pro, x64dbg, Cuckoo Sandbox
[OUTPUT] Generate IOCs for detection tools`;
    },
    
    forensics: () => {
        return `=== DIGITAL FORENSICS GUIDE ===
┌─────────────────────────────────────────────────┐
│ 1. PRESERVATION                                │
│    • Chain of custody documentation            │
│    • Write-blockers for imaging                │
│    • Cryptographic hash verification           │
│    • Evidence bags/labeling                    │
├─────────────────────────────────────────────────┤
│ 2. ACQUISITION                                 │
│    • Disk imaging (dd, FTK Imager)             │
│    • Memory capture (Volatility, LiME)         │
│    • Network logs preservation                 │
│    • Cloud forensics acquisition               │
├─────────────────────────────────────────────────┤
│ 3. ANALYSIS                                    │
│    • File system analysis (NTFS, ext4, APFS)   │
│    • Deleted file recovery                     │
│    • Timeline analysis                         │
│    • Registry analysis (Windows)               │
│    • Log analysis                              │
├─────────────────────────────────────────────────┤
│ 4. MEMORY FORENSICS                            │
│    • Process analysis                          │
│    • Network connections                       │
│    • Rootkit detection                         │
│    • Malware extraction                        │
├─────────────────────────────────────────────────┤
│ 5. REPORTING                                   │
│    • Expert report writing                     │
│    • Visual timeline creation                  │
│    • Evidence presentation                     │
│    • Court testimony preparation               │
└─────────────────────────────────────────────────┘

[TOOLS] FTK, EnCase, Autopsy, Volatility, Wireshark
[CERTIFICATION] GCFE, GCFA, EnCE recommended`;
    },
    
    compliance_check: () => {
        return `=== COMPLIANCE FRAMEWORK OVERVIEW ===
┌─────────────────────────────────────────────────┐
│ ISO 27001                                      │
│    • Information Security Management System    │
│    • 114 controls across 14 clauses           │
│    • Risk-based approach                      │
│    • Continuous improvement                    │
├─────────────────────────────────────────────────┤
│ GDPR                                           │
│    • Data protection for EU citizens           │
│    • 7 key principles                         │
│    • Rights of data subjects                   │
│    • Breach notification (72 hours)            │
├─────────────────────────────────────────────────┤
│ NIST CSF                                       │
│    • 5 core functions                         │
│    • 23 categories                            │
│    • 108 subcategories                        │
│    • Tiered implementation                    │
├─────────────────────────────────────────────────┤
│ PCI-DSS                                        │
│    • Payment card data security               │
│    • 12 requirements                          │
│    • 4 compliance levels                      │
│    • Quarterly scans required                 │
├─────────────────────────────────────────────────┤
│ SOX                                            │
│    • Financial reporting controls              │
│    • Section 302 (certification)              │
│    • Section 404 (internal controls)          │
│    • IT general controls                      │
├─────────────────────────────────────────────────┤
│ DORA                                           │
│    • Digital Operational Resilience            │
│    • ICT risk management                      │
│    • Incident reporting                       │
│    • Resilience testing                       │
└─────────────────────────────────────────────────┘

[AUDIT] Regular compliance assessments required
[UPDATE] Monitor regulatory changes`;
    },
    
    clear: () => {
        const output = document.getElementById('terminal-output');
        if (output) {
            output.innerHTML = '<div class="terminal-line">Terminal cleared. Type "help" for commands.</div>';
        }
        return '';
    }
};

// ============================================
// DOM CONTENT LOADED - MAIN INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    console.log('ROCyber System Initializing...');
    
    // ========================================
    // INTRO SEQUENCE
    // ========================================
    const introSequence = document.getElementById('intro-sequence');
    const introDelay = isMobile() ? 3000 : 5000;
    setTimeout(() => {
        if (introSequence) {
            introSequence.style.display = 'none';
        }
    }, introDelay);
    
    // ========================================
    // RECRUITMENT PANEL (Ctrl+Shift+A)
    // ========================================
    const recruitmentPanel = document.getElementById('recruitment-panel');
    let ctrlPressed = false;
    let shiftPressed = false;
    let aPressed = false;
    
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
        
        const storedCode = localStorage.getItem('verificationCode');
        if (storedCode) verificationCodeSpan.textContent = storedCode;
    }
    
    // ========================================
    // PIP-BOY INVENTORY SYSTEM
    // ========================================
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
            if (e.key === 'Escape') {
                pipBoyInventory.classList.remove('active');
            }
        });
    }
    
    // Inventory tabs switching
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
    
    // ========================================
    // YOUTUBE PLAYER SETUP
    // ========================================
    loadYouTubeAPI();
    
    // Setup YouTube controls after API loads
    setTimeout(() => {
        const playBtn = document.getElementById('yt-play-btn');
        const pauseBtn = document.getElementById('yt-pause-btn');
        const stopBtn = document.getElementById('yt-stop-btn');
        const muteBtn = document.getElementById('yt-mute-btn');
        const loadBtn = document.getElementById('load-yt-btn');
        const urlInput = document.getElementById('yt-url');
        const presetBtns = document.querySelectorAll('.playlist-preset');
        
        if (playBtn) playBtn.addEventListener('click', playYouTube);
        if (pauseBtn) pauseBtn.addEventListener('click', pauseYouTube);
        if (stopBtn) stopBtn.addEventListener('click', stopYouTube);
        if (muteBtn) muteBtn.addEventListener('click', toggleMuteYouTube);
        
        if (loadBtn && urlInput) {
            loadBtn.addEventListener('click', () => loadYouTubeVideo(urlInput.value));
            urlInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') loadYouTubeVideo(urlInput.value);
            });
        }
        
        presetBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const videoId = btn.getAttribute('data-id');
                if (videoId && videoId !== 'YOUR_VIDEO_ID_HERE') {
                    loadYouTubeVideo(videoId);
                    if (urlInput) urlInput.value = videoId;
                } else if (videoId === 'YOUR_VIDEO_ID_HERE') {
                    alert('🔧 KONFIGURACJA: Zamień "YOUR_VIDEO_ID_HERE" na ID swojego filmu z YouTube!\n\nID filmu znajdziesz w linku:\nhttps://www.youtube.com/watch?v=XXXXXXXXXXX');
                }
            });
        });
        
        const lastVideo = localStorage.getItem('lastYouTubeVideo');
        if (lastVideo && urlInput) urlInput.value = lastVideo;
    }, 1000);
    
    // ========================================
    // PIP-BOY TERMINAL
    // ========================================
    const pipTerminalCommand = document.getElementById('pipTerminalCommand');
    const pipTerminalOutput = document.getElementById('pipTerminalOutput');
    
    if (pipTerminalCommand && pipTerminalOutput) {
        pipTerminalCommand.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const fullCommand = this.value.trim();
                this.value = '';
                if (!fullCommand) return;
                
                // Display command
                const commandLine = document.createElement('div');
                commandLine.className = 'terminal-line';
                commandLine.innerHTML = `<span class="terminal-prompt">$</span> ${fullCommand}`;
                pipTerminalOutput.appendChild(commandLine);
                
                // Parse command and argument
                const parts = fullCommand.toLowerCase().split(' ');
                const command = parts[0];
                const argument = parts.slice(1).join(' ');
                
                let result;
                if (pipCommands[command]) {
                    result = pipCommands[command](argument);
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
    
    // ========================================
    // MAIN NAVIGATION
    // ========================================
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
                
                // Close pip-boy inventory
                if (pipBoyInventory) pipBoyInventory.classList.remove('active');
            });
        });
    }
    
    // ========================================
    // MAIN TERMINAL
    // ========================================
    const terminalCommand = document.getElementById('terminal-command');
    const terminalOutput = document.getElementById('terminal-output');
    
    if (terminalCommand && terminalOutput) {
        terminalCommand.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                const command = this.value.trim().toLowerCase();
                this.value = '';
                if (!command) return;
                
                // Display command
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
    
    // ========================================
    // QUIZ FUNCTIONALITY
    // ========================================
    const quizOptions = document.querySelectorAll('.quiz-option');
    let quizScore = 0;
    let quizAnswered = 0;
    const totalQuizQuestions = document.querySelectorAll('.quiz-question').length;
    
    quizOptions.forEach(option => {
        option.addEventListener('click', function() {
            const question = this.closest('.quiz-question');
            const feedback = question.querySelector('.quiz-feedback');
            const isCorrect = this.dataset.correct === 'true';
            
            if (question.classList.contains('answered')) return;
            question.classList.add('answered');
            quizAnswered++;
            
            // Disable all options in this question
            question.querySelectorAll('.quiz-option').forEach(opt => {
                opt.style.background = 'rgba(20, 20, 30, 0.5)';
                opt.style.borderColor = 'rgba(0, 247, 255, 0.1)';
                opt.style.cursor = 'default';
                opt.style.pointerEvents = 'none';
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
                
                // Highlight correct answer
                question.querySelectorAll('.quiz-option').forEach(opt => {
                    if (opt.dataset.correct === 'true') {
                        opt.style.background = 'rgba(85, 255, 85, 0.15)';
                        opt.style.borderColor = '#55ff55';
                    }
                });
            }
            
            // Show final score when all questions answered
            if (quizAnswered === totalQuizQuestions) {
                const scorePercentage = Math.round((quizScore / totalQuizQuestions) * 100);
                const quizContainer = document.querySelector('.quiz-container');
                const existingScore = quizContainer.querySelector('.final-score');
                
                if (!existingScore) {
                    const scoreMessage = document.createElement('div');
                    scoreMessage.className = 'final-score';
                    scoreMessage.innerHTML = `
                        <i class="fas fa-chart-line"></i> 
                        Quiz Complete! Score: ${quizScore}/${totalQuizQuestions} (${scorePercentage}%)
                        <br>
                        <small>${scorePercentage >= 75 ? 'Excellent! You know your security!' : 'Review the materials and try again.'}</small>
                    `;
                    quizContainer.appendChild(scoreMessage);
                }
            }
        });
    });
    
    // ========================================
    // DYNAMIC GRADIENT (DESKTOP ONLY)
    // ========================================
    const gradient = document.querySelector('.cyber-gradient');
    if (gradient && !isMobile()) {
        document.addEventListener('mousemove', (e) => {
            const x = e.clientX / window.innerWidth;
            const y = e.clientY / window.innerHeight;
            gradient.style.background = `
                linear-gradient(${135 + x * 45}deg, rgba(255, 255, 0, 0.08) 0%, transparent 50%),
                linear-gradient(${-135 + y * 45}deg, rgba(221, 0, 255, 0.08) 0%, transparent 50%),
                radial-gradient(circle at ${x * 100}% ${y * 100}%, rgba(0, 247, 255, 0.05) 0%, transparent 70%)
            `;
        });
    }
    
    // ========================================
    // PARALLAX EFFECT (DESKTOP ONLY)
    // ========================================
    if (!isMobile()) {
        const floatingElements = document.querySelectorAll('.floating-element');
        document.addEventListener('mousemove', (e) => {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;
            
            floatingElements.forEach((element, index) => {
                const speed = (index + 1) * 0.04;
                const x = (mouseX - 0.5) * 120 * speed;
                const y = (mouseY - 0.5) * 120 * speed;
                element.style.transform = `translate(${x}px, ${y}px)`;
            });
        });
    }
    
    // ========================================
    // SMOOTH SCROLL FOR ANCHOR LINKS
    // ========================================
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
    
    // ========================================
    // WINDOW RESIZE HANDLER
    // ========================================
    window.addEventListener('resize', () => {
        if (isMobile() && pipBoyInventory && pipBoyInventory.classList.contains('active')) {
            pipBoyInventory.style.width = '100%';
        }
    });
    
    // ========================================
    // PREVENT ZOOM ON DOUBLE TAP (MOBILE)
    // ========================================
    let lastTouchEnd = 0;
    document.addEventListener('touchend', function(event) {
        const now = Date.now();
        if (now - lastTouchEnd <= 300) {
            event.preventDefault();
        }
        lastTouchEnd = now;
    }, false);
    
    // ========================================
    // CONSOLE WELCOME MESSAGE
    // ========================================
    console.log('%c🔐 ROCyber Security System Online', 'color: #00ff00; font-size: 18px; font-weight: bold;');
    console.log('%c┌─────────────────────────────────────────┐', 'color: #ffff00');
    console.log('%c│ Welcome to ROCyber Solutions Portfolio  │', 'color: #ffff00');
    console.log('%c│                                         │', 'color: #ffff00');
    console.log('%c│ 🔑 Tip: Press Ctrl+Shift+A for          │', 'color: #ff8800');
    console.log('%c│    Recruitment Verification Panel      │', 'color: #ff8800');
    console.log('%c│                                         │', 'color: #ffff00');
    console.log('%c│ 🎵 Tip: Use Pip-Boy (right side) for    │', 'color: #dd00ff');
    console.log('%c│    YouTube music player and terminal    │', 'color: #dd00ff');
    console.log('%c└─────────────────────────────────────────┘', 'color: #ffff00');
    
    console.log('%c🚀 System ready. Enjoy the experience!', 'color: #00f7ff; font-size: 14px;');
});

// Expose functions globally for debugging
window.pipCommands = pipCommands;
window.mainCommands = mainCommands;
window.playYouTube = playYouTube;
window.pauseYouTube = pauseYouTube;
window.stopYouTube = stopYouTube;
window.loadYouTubeVideo = loadYouTubeVideo;
