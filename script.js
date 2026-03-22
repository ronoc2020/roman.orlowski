
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

// Initialize Particles.js
if (document.getElementById('particles-js')) {
  particlesJS('particles-js', particleConfig);
}

// ===== PIP-BOY FULL SCREEN MODE =====
function initializeFullscreen() {
  const fullscreenBtn = document.getElementById('fullscreen-btn');
  const pipBoyInventory = document.querySelector('.pip-boy-inventory');
  
  if (!fullscreenBtn || !pipBoyInventory) {
    console.log('Fullscreen elements not found, retrying...');
    setTimeout(initializeFullscreen, 100);
    return;
  }
  
  console.log('Fullscreen initialized');
  
  fullscreenBtn.addEventListener('click', function(e) {
    e.preventDefault();
    pipBoyInventory.classList.toggle('fullscreen');
    
    if (pipBoyInventory.classList.contains('fullscreen')) {
      fullscreenBtn.innerHTML = '<i class="fas fa-compress"></i> COLLAPSE';
      fullscreenBtn.title = 'Exit Full Screen Mode';
    } else {
      fullscreenBtn.innerHTML = '<i class="fas fa-expand"></i> EXPAND';
      fullscreenBtn.title = 'Toggle Full Screen Mode';
    }
  });
  
  // Close fullscreen on Escape key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && pipBoyInventory.classList.contains('fullscreen')) {
      pipBoyInventory.classList.remove('fullscreen');
      fullscreenBtn.innerHTML = '<i class="fas fa-expand"></i> EXPAND';
      fullscreenBtn.title = 'Toggle Full Screen Mode';
    }
  });
}

// Initialize fullscreen when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeFullscreen);
} else {
  initializeFullscreen();
}

// ===== NAVIGATION & SECTION SWITCHING =====
document.addEventListener('DOMContentLoaded', function() {
  const navItems = document.querySelectorAll('.nav-item');
  const sections = document.querySelectorAll('.section');

  navItems.forEach(item => {
    item.addEventListener('click', function() {
      const targetSection = this.getAttribute('data-section');
      
      sections.forEach(section => {
        section.classList.remove('visible');
      });
      
      navItems.forEach(nav => {
        nav.classList.remove('active');
      });
      
      document.getElementById(targetSection).classList.add('visible');
      this.classList.add('active');
    });
  });
});

// ===== INVENTORY TAB SWITCHING =====
document.addEventListener('DOMContentLoaded', function() {
  const tabs = document.querySelectorAll('.inventory-tab');
  const contents = document.querySelectorAll('.inventory-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', function() {
      const tabName = this.getAttribute('data-tab');
      
      tabs.forEach(t => t.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));
      
      this.classList.add('active');
      document.getElementById(tabName).classList.add('active');
    });
  });
});

// ===== TERMINAL FUNCTIONALITY =====
document.addEventListener('DOMContentLoaded', function() {
  const terminalInput = document.getElementById('terminal-input');
  const terminalOutput = document.getElementById('terminal-output');

  if (!terminalInput || !terminalOutput) return;

  const commands = {
    help: `Available commands:
  • scan – Run security vulnerability scan
  • status – System status report
  • threat – Threat assessment
  • clear – Clear terminal
  • whoami – Display current user
  • date – Show current date/time`,
    
    scan: `Security Scan Results:
  ✓ Firewall: Active
  ✓ Antivirus: Updated
  ⚠ Patches: 3 available
  ✗ Weak passwords detected: 2 accounts
Security Assessment: Implement firewall rules and close unnecessary ports.`,
    
    status: `System Status:
  OS: Secure Linux v2.0
  Uptime: 47 days 12 hours
  CPU: 8 cores @ 2.4GHz
  Memory: 16GB (78% used)
  Disk: 512GB (65% used)
  Network: Connected (Encrypted)`,
    
    threat: `Threat Assessment Report:
  Critical Threats: 0
  High Priority: 2
  Medium Priority: 5
  Low Priority: 12
  
  Recent Activity:
  • Brute force attempt blocked (192.168.1.100)
  • Suspicious login from new location
  • Malware signature detected in quarantine`,
    
    whoami: 'Roman Orłowski | vCISO | Strategic Cybersecurity Leadership',
    date: new Date().toString(),
    clear: 'CLEAR'
  };

  terminalInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      const command = this.value.toLowerCase().trim();
      const output = document.createElement('div');
      output.className = 'terminal-line';
      
      output.innerHTML = `<span class="terminal-prompt">$</span> ${command}`;
      terminalOutput.appendChild(output);
      
      if (command === 'clear') {
        terminalOutput.innerHTML = '';
      } else {
        const result = document.createElement('div');
        result.className = 'terminal-result';
        result.textContent = commands[command] || `Command not found: ${command}. Type 'help' for available commands.`;
        terminalOutput.appendChild(result);
      }
      
      terminalOutput.scrollTop = terminalOutput.scrollHeight;
      this.value = '';
    }
  });
});

// ===== QUIZ FUNCTIONALITY =====
document.addEventListener('DOMContentLoaded', function() {
  const quizOptions = document.querySelectorAll('.quiz-option');
  const quizResults = document.querySelector('.quiz-results');
  let scores = { ethical: 0, unethical: 0, neutral: 0, manipulative: 0 };
  let answeredQuestions = 0;
  const totalQuestions = document.querySelectorAll('.quiz-question').length;

  quizOptions.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.quiz-question');
      const alreadyAnswered = question.querySelector('.quiz-option.selected');
      
      if (!alreadyAnswered) {
        answeredQuestions++;
      }

      question.querySelectorAll('.quiz-option').forEach(opt => {
        opt.classList.remove('selected');
      });

      this.classList.add('selected');
      const value = this.getAttribute('data-value');
      scores[value]++;

      if (answeredQuestions === totalQuestions) {
        displayQuizResults();
      }
    });
  });

  function displayQuizResults() {
    const ethicalScore = Math.round((scores.ethical / totalQuestions) * 100);
    const culturalFit = Math.round(((scores.ethical + (totalQuestions - scores.unethical - scores.manipulative)) / totalQuestions) * 100);
    const redFlags = scores.unethical + scores.manipulative;

    document.getElementById('ethical-score').textContent = ethicalScore;
    document.getElementById('cultural-score').textContent = culturalFit;
    document.getElementById('red-flags').textContent = redFlags;

    let message = '';
    if (ethicalScore >= 80) {
      message = '<i class="fas fa-check-circle"></i> Excellent ethical alignment. You demonstrate strong integrity and cultural fit.';
    } else if (ethicalScore >= 60) {
      message = '<i class="fas fa-star"></i> Good ethical foundation. Some areas for improvement in consistency.';
    } else if (ethicalScore >= 40) {
      message = '<i class="fas fa-exclamation-triangle"></i> Moderate concerns. Consider reflecting on your values and decision-making.';
    } else {
      message = '<i class="fas fa-times-circle"></i> Significant red flags detected. This role may not be a good fit.';
    }

    if (quizResults) {
      quizResults.style.display = 'block';
      quizResults.scrollIntoView({ behavior: 'smooth' });
    }
  }
});

// ===== DRAGGABLE MUSIC PLAYER =====
(function() {
  const player = document.querySelector('.draggable-player');
  if (!player) return;

  let isDragging = false;
  let currentX;
  let currentY;
  let initialX;
  let initialY;

  player.addEventListener('mousedown', dragStart);
  player.addEventListener('touchstart', dragStart);
  document.addEventListener('mousemove', drag);
  document.addEventListener('touchmove', drag);
  document.addEventListener('mouseup', dragEnd);
  document.addEventListener('touchend', dragEnd);

  function dragStart(e) {
    initialX = e.clientX - player.offsetLeft || e.touches[0].clientX - player.offsetLeft;
    initialY = e.clientY - player.offsetTop || e.touches[0].clientY - player.offsetTop;
    isDragging = true;
  }

  function drag(e) {
    if (isDragging) {
      e.preventDefault();
      currentX = (e.clientX || e.touches[0].clientX) - initialX;
      currentY = (e.clientY || e.touches[0].clientY) - initialY;
      player.style.transform = `translate(${currentX}px, ${currentY}px)`;
    }
  }

  function dragEnd() {
    isDragging = false;
  }
})();

// ===== ASSESSMENT FUNCTIONALITY =====
document.addEventListener('DOMContentLoaded', function() {
  const assessmentOptions = document.querySelectorAll('.assessment-option');
  const assessmentResults = document.querySelector('.assessment-results');
  let scores = { ethical: 0, unethical: 0, neutral: 0, manipulative: 0 };
  let answeredQuestions = 0;
  const totalQuestions = document.querySelectorAll('.assessment-question').length;

  assessmentOptions.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.assessment-question');
      const alreadyAnswered = question.querySelector('.assessment-option.selected');
      
      if (!alreadyAnswered) {
        answeredQuestions++;
      }

      // Remove previous selection
      question.querySelectorAll('.assessment-option').forEach(opt => {
        opt.classList.remove('selected');
      });

      // Mark current selection
      this.classList.add('selected');
      const value = this.getAttribute('data-value');
      scores[value]++;

      // Show results when all questions are answered
      if (answeredQuestions === totalQuestions) {
        displayAssessmentResults();
      }
    });
  });

  function displayAssessmentResults() {
    const ethicalScore = Math.round((scores.ethical / totalQuestions) * 100);
    const redFlags = scores.unethical + scores.manipulative;
    const culturalFit = Math.round(((scores.ethical + (totalQuestions - redFlags)) / totalQuestions) * 100);

    document.getElementById('ethical-score').textContent = ethicalScore + '%';
    document.getElementById('cultural-score').textContent = culturalFit + '%';
    document.getElementById('red-flags').textContent = redFlags;

    let verdict = '';
    let verdictClass = '';

    if (ethicalScore >= 80) {
      verdict = '<i class="fas fa-check-circle"></i> <strong>SAFE TO JOIN</strong> – Excellent ethical alignment. This organization demonstrates strong integrity and cultural fit for a vCISO.';
      verdictClass = 'verdict-safe';
    } else if (ethicalScore >= 60) {
      verdict = '<i class="fas fa-exclamation-circle"></i> <strong>PROCEED WITH CAUTION</strong> – Good ethical foundation with some areas of concern. Recommend further investigation.';
      verdictClass = 'verdict-caution';
    } else if (ethicalScore >= 40) {
      verdict = '<i class="fas fa-exclamation-triangle"></i> <strong>INVESTIGATE FURTHER</strong> – Significant red flags detected. Consider declining or negotiating major changes.';
      verdictClass = 'verdict-warning';
    } else {
      verdict = '<i class="fas fa-times-circle"></i> <strong>DO NOT JOIN</strong> – Toxic, unethical, or deceptive environment. This role is not a good fit.';
      verdictClass = 'verdict-danger';
    }

    const verdictElement = document.getElementById('results-verdict');
    verdictElement.className = 'results-verdict ' + verdictClass;
    verdictElement.innerHTML = verdict;

    // Generate encrypted verdict (SHA-256)
    const verdictText = `ROCS Assessment - Ethical: ${ethicalScore}% | Cultural Fit: ${culturalFit}% | Red Flags: ${redFlags} | Verdict: ${verdict.replace(/<[^>]*>/g, '')}`;
    const encryptedVerdictText = CryptoJS.SHA256(verdictText).toString();
    const encryptedTextarea = document.getElementById('encrypted-verdict');
    encryptedTextarea.value = encryptedVerdictText;

    // Show results section
    document.getElementById('assessment-results').style.display = 'block';
    document.getElementById('assessment-results').scrollIntoView({ behavior: 'smooth' });
  }
});

// Initialize Assessment on page load
document.addEventListener('DOMContentLoaded', function() {
  initializeAssessment();
});

function initializeAssessment() {
  const options = document.querySelectorAll('.assessment-option');
  let scores = { ethical: 0, unethical: 0, neutral: 0, manipulative: 0 };
  let answeredCount = 0;
  const totalQuestions = document.querySelectorAll('.assessment-question').length;

  options.forEach(option => {
    option.addEventListener('click', function() {
      const question = this.closest('.assessment-question');
      const alreadyAnswered = question.querySelector('.assessment-option.selected');

      if (!alreadyAnswered) {
        answeredCount++;
      }

      // Remove previous selection
      question.querySelectorAll('.assessment-option').forEach(opt => {
        opt.classList.remove('selected');
      });

      // Mark current selection
      this.classList.add('selected');
      const value = this.getAttribute('data-value');
      scores[value]++;

      // Show results when all questions are answered
      if (answeredCount === totalQuestions) {
        displayAssessmentResults(scores, totalQuestions);
      }
    });
  });
}

function displayAssessmentResults(scores, totalQuestions) {
  const ethicalScore = Math.round((scores.ethical / totalQuestions) * 100);
  const redFlags = scores.unethical + scores.manipulative;
  const culturalFit = Math.round(((scores.ethical + (totalQuestions - redFlags)) / totalQuestions) * 100);

  document.getElementById('ethical-score').textContent = ethicalScore + '%';
  document.getElementById('cultural-score').textContent = culturalFit + '%';
  document.getElementById('red-flags').textContent = redFlags;

  let verdict = '';
  let verdictClass = '';

  if (ethicalScore >= 80) {
    verdict = '<i class="fas fa-check-circle"></i> <strong>SAFE TO JOIN</strong> – Excellent ethical alignment. This organization demonstrates strong integrity and cultural fit for a vCISO.';
    verdictClass = 'verdict-safe';
  } else if (ethicalScore >= 60) {
    verdict = '<i class="fas fa-exclamation-circle"></i> <strong>PROCEED WITH CAUTION</strong> – Good ethical foundation with some areas of concern. Recommend further investigation.';
    verdictClass = 'verdict-caution';
  } else if (ethicalScore >= 40) {
    verdict = '<i class="fas fa-exclamation-triangle"></i> <strong>INVESTIGATE FURTHER</strong> – Significant red flags detected. Consider declining or negotiating major changes.';
    verdictClass = 'verdict-warning';
  } else {
    verdict = '<i class="fas fa-times-circle"></i> <strong>DO NOT JOIN</strong> – Toxic, unethical, or deceptive environment. This role is not a good fit.';
    verdictClass = 'verdict-danger';
  }

  const verdictElement = document.getElementById('results-verdict');
  verdictElement.className = 'results-verdict ' + verdictClass;
  verdictElement.innerHTML = verdict;

  // Generate encrypted verdict (SHA-256)
  const verdictText = `ROCS Assessment - Ethical: ${ethicalScore}% | Cultural Fit: ${culturalFit}% | Red Flags: ${redFlags} | Verdict: ${verdict.replace(/<[^>]*>/g, '')}`;
  const encryptedVerdictText = CryptoJS.SHA256(verdictText).toString();
  const encryptedTextarea = document.getElementById('encrypted-verdict');
  encryptedTextarea.value = encryptedVerdictText;

  // Show results section
  document.getElementById('assessment-results').style.display = 'block';
  document.getElementById('assessment-results').scrollIntoView({ behavior: 'smooth' });
}

function copyVerdictToClipboard() {
  const textarea = document.getElementById('encrypted-verdict');
  textarea.select();
  document.execCommand('copy');
  
  const btn = document.getElementById('copy-verdict');
  const originalText = btn.innerHTML;
  btn.innerHTML = '<i class="fas fa-check"></i> COPIED!';
  
  setTimeout(() => {
    btn.innerHTML = originalText;
  }, 2000);
}

// ===== ENHANCED ASSESSMENT ANALYSIS =====
function analyzeAssessmentResponses(scores, totalQuestions) {
  const ethicalScore = Math.round((scores.ethical / totalQuestions) * 100);
  const redFlags = scores.unethical + scores.manipulative;
  const culturalFit = Math.round(((scores.ethical + (totalQuestions - redFlags)) / totalQuestions) * 100);
  
  // Detect patterns and inconsistencies
  const patterns = {
    avoidance: scores.manipulative > (totalQuestions * 0.4), // More than 40% evasive answers
    unethical_tendency: scores.unethical > (totalQuestions * 0.3), // More than 30% unethical answers
    inconsistency: Math.abs(scores.ethical - scores.neutral) > (totalQuestions * 0.5), // Large variance
    red_flag_count: redFlags
  };
  
  return {
    ethicalScore,
    culturalFit,
    redFlags,
    patterns
  };
}

function generateRedFlags(scores, totalQuestions) {
  const flags = [];
  const analysis = analyzeAssessmentResponses(scores, totalQuestions);
  
  if (analysis.patterns.avoidance) {
    flags.push('🚩 Excessive evasiveness detected – recruiter avoiding direct answers');
  }
  if (analysis.patterns.unethical_tendency) {
    flags.push('🚩 Unethical practices normalized – concerning compliance attitude');
  }
  if (analysis.patterns.inconsistency) {
    flags.push('🚩 Inconsistent responses – possible deception or lack of clarity');
  }
  if (analysis.redFlags >= 8) {
    flags.push('🚩 CRITICAL: Multiple serious red flags – high risk environment');
  }
  
  return flags;
}
