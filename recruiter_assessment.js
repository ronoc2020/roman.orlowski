// ===== ROCS PIP-BOY 3000 v2.0 - RECRUITER INVESTIGATION MODULE =====

const RECRUITER_QUESTIONS = [
  {
    id: 1,
    question: "Your company faced a critical security breach last year. How was it handled, and what was the employee communication strategy?",
    options: [
      { text: "We disclosed it immediately to all stakeholders and took full responsibility. Transparency is our core value.", value: "ethical" },
      { text: "We handled it internally first, then informed relevant parties when necessary. Discretion is important.", value: "neutral" },
      { text: "We consulted with legal before any communication. They advised us on the best approach.", value: "unethical" },
      { text: "We haven't had any breaches. Our security is flawless.", value: "manipulative" }
    ]
  },
  {
    id: 2,
    question: "How does your organization handle disagreement between senior management and junior staff on security matters?",
    options: [
      { text: "Junior staff are encouraged to challenge decisions with data. The best idea wins, regardless of rank.", value: "ethical" },
      { text: "We have a formal escalation process, but ultimately leadership decides what's best.", value: "neutral" },
      { text: "Disagreement is discouraged. We need unity and trust in leadership.", value: "unethical" },
      { text: "Junior staff are expected to implement decisions without questioning them.", value: "manipulative" }
    ]
  },
  {
    id: 3,
    question: "Tell me about a time when someone admitted a significant mistake at work. How was it handled?",
    options: [
      { text: "We treated it as a learning opportunity. The person was supported, and we improved processes.", value: "ethical" },
      { text: "The person was reprimanded, but we learned from it and moved forward.", value: "neutral" },
      { text: "Mistakes like that rarely happen because we have strict controls.", value: "unethical" },
      { text: "People don't usually admit mistakes openly. They're afraid of consequences.", value: "manipulative" }
    ]
  },
  {
    id: 4,
    question: "What is the real reason this vCISO position is open? (Be honest.)",
    options: [
      { text: "We're scaling security operations and need expert leadership at the executive level.", value: "ethical" },
      { text: "Our previous CISO left, and we need someone to fill the gap quickly.", value: "neutral" },
      { text: "We're facing regulatory pressure and need someone to handle compliance.", value: "unethical" },
      { text: "We're not entirely sure. HR posted the position, and we're hoping to find the right fit.", value: "manipulative" }
    ]
  },
  {
    id: 5,
    question: "If I discovered that a C-level executive was bypassing security controls for convenience, how would you expect me to handle it?",
    options: [
      { text: "Report it immediately through our ethics channel. No exceptions, regardless of rank.", value: "ethical" },
      { text: "Approach the executive privately first. We handle things diplomatically.", value: "neutral" },
      { text: "Inform your direct manager and let them decide the best course of action.", value: "unethical" },
      { text: "Document it quietly and wait for the right moment to address it.", value: "manipulative" }
    ]
  },
  {
    id: 6,
    question: "What is the average tenure of security professionals in your organization?",
    options: [
      { text: "3-5+ years. We invest in career development and work-life balance.", value: "ethical" },
      { text: "2-3 years. It's a demanding field, and people move on naturally.", value: "neutral" },
      { text: "1-2 years. We have high turnover, but we're always hiring.", value: "unethical" },
      { text: "I'm not sure. HR handles that.", value: "manipulative" }
    ]
  },
  {
    id: 7,
    question: "What are the three biggest challenges your organization faces in security right now?",
    options: [
      { text: "Legacy systems, skill gaps, and executive alignment on risk. We're actively addressing each.", value: "ethical" },
      { text: "Budget constraints, compliance deadlines, and talent acquisition.", value: "neutral" },
      { text: "We're doing pretty well. Our main challenge is keeping up with new threats.", value: "unethical" },
      { text: "I don't really know. That's more of a technical question.", value: "manipulative" }
    ]
  },
  {
    id: 8,
    question: "How does your company define 'success' for a security leader?",
    options: [
      { text: "Reducing risk while enabling business growth. Security and business are partners.", value: "ethical" },
      { text: "Meeting compliance requirements and preventing breaches.", value: "neutral" },
      { text: "Implementing the latest security tools and technologies.", value: "unethical" },
      { text: "Keeping the executive team happy and out of the news.", value: "manipulative" }
    ]
  },
  {
    id: 9,
    question: "If your company's practices conflicted with industry best practices, how would you handle it?",
    options: [
      { text: "I'd present the data, recommend changes, and escalate if necessary. Integrity comes first.", value: "ethical" },
      { text: "I'd try to align practices gradually without rocking the boat.", value: "neutral" },
      { text: "I'd follow company policy. That's what I'm hired to do.", value: "unethical" },
      { text: "I'd keep quiet. It's not my job to question leadership.", value: "manipulative" }
    ]
  },
  {
    id: 10,
    question: "How diverse is your security leadership team, and how is diversity valued?",
    options: [
      { text: "We actively recruit diverse talent and have diverse leadership. It's a strategic priority.", value: "ethical" },
      { text: "We hire the best people regardless of background. Diversity happens naturally.", value: "neutral" },
      { text: "We're working on it. It's a challenge in the tech industry.", value: "unethical" },
      { text: "We focus on skills and experience. Diversity isn't a primary concern.", value: "manipulative" }
    ]
  },
  {
    id: 11,
    question: "Has your organization ever asked you to compromise on security to meet a deadline or business goal?",
    options: [
      { text: "Never. We've delayed projects to maintain security standards.", value: "ethical" },
      { text: "Occasionally, but we mitigate the risks and document the decision.", value: "neutral" },
      { text: "Yes, frequently. Business always comes first.", value: "unethical" },
      { text: "It's happened, but I don't think it's appropriate to discuss.", value: "manipulative" }
    ]
  },
  {
    id: 12,
    question: "How does your organization handle emerging threats and new security paradigms?",
    options: [
      { text: "We invest in continuous learning and adapt quickly. We see change as an opportunity.", value: "ethical" },
      { text: "We monitor trends and update our strategy annually.", value: "neutral" },
      { text: "We stick with proven methods. New trends come and go.", value: "unethical" },
      { text: "We react when something happens. Proactive planning isn't really our style.", value: "manipulative" }
    ]
  },
  {
    id: 13,
    question: "If a security incident occurred due to a decision I made, how would your organization handle it?",
    options: [
      { text: "We'd conduct a blameless post-mortem, focus on learning, and improve systems.", value: "ethical" },
      { text: "We'd investigate, document it, and use it to improve processes.", value: "neutral" },
      { text: "You'd be held responsible, but we'd work together to fix it.", value: "unethical" },
      { text: "You'd likely face consequences. We can't afford mistakes at this level.", value: "manipulative" }
    ]
  },
  {
    id: 14,
    question: "How does your organization value security professionals relative to other departments?",
    options: [
      { text: "Security is seen as a strategic asset. Compensation is competitive and reflects that.", value: "ethical" },
      { text: "We pay market rate. Security is important, but so are other functions.", value: "neutral" },
      { text: "We pay less than market because security is a cost center, not revenue-generating.", value: "unethical" },
      { text: "I'm not sure. That's an HR question.", value: "manipulative" }
    ]
  },
  {
    id: 15,
    question: "What would you say if I told you I'm considering declining this offer?",
    options: [
      { text: "I'd respect your decision and ask what concerns I can address. Your fit matters.", value: "ethical" },
      { text: "I'd be disappointed and try to convince you of the opportunity.", value: "neutral" },
      { text: "I'd be surprised and want to know what's wrong with our offer.", value: "unethical" },
      { text: "I'd tell you you're making a mistake. This is a great opportunity.", value: "manipulative" }
    ]
  }
];

// Initialize Assessment
document.addEventListener('DOMContentLoaded', function() {
  initializeRecruiterAssessment();
  setupTerminalCommands();
  setupExpandableUI();
});

function initializeRecruiterAssessment() {
  const container = document.getElementById('assessment-container');
  if (!container) return;

  let assessmentHTML = '';
  RECRUITER_QUESTIONS.forEach((q, index) => {
    assessmentHTML += `
      <div class="assessment-question" data-question-id="${q.id}">
        <h4><i class="fas fa-circle-question"></i> Q${index + 1}: ${q.question}</h4>
        <div class="assessment-options">
          ${q.options.map((opt, optIndex) => `
            <div class="assessment-option" data-value="${opt.value}" data-option-index="${optIndex}">
              <span class="option-letter">${String.fromCharCode(65 + optIndex)}</span>
              <span class="option-text">${opt.text}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  });

  container.innerHTML = assessmentHTML;

  // Add event listeners to options
  const options = document.querySelectorAll('.assessment-option');
  let scores = { ethical: 0, unethical: 0, neutral: 0, manipulative: 0 };
  let answeredCount = 0;

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
      if (answeredCount === RECRUITER_QUESTIONS.length) {
        displayAssessmentResults(scores);
      }
    });
  });
}

function displayAssessmentResults(scores) {
  const ethicalScore = Math.round((scores.ethical / RECRUITER_QUESTIONS.length) * 100);
  const redFlags = scores.unethical + scores.manipulative;
  const culturalFit = Math.round(((scores.ethical + (RECRUITER_QUESTIONS.length - redFlags)) / RECRUITER_QUESTIONS.length) * 100);

  document.getElementById('ethical-score').textContent = ethicalScore + '%';
  document.getElementById('cultural-score').textContent = culturalFit + '%';
  document.getElementById('red-flags').textContent = redFlags;

  let verdict = '';
  let verdictClass = '';

  if (ethicalScore >= 80) {
    verdict = '<i class="fas fa-check-circle"></i> <strong>SAFE TO JOIN</strong> - Excellent ethical alignment. This organization demonstrates strong integrity and cultural fit for a vCISO.';
    verdictClass = 'verdict-safe';
  } else if (ethicalScore >= 60) {
    verdict = '<i class="fas fa-exclamation-circle"></i> <strong>PROCEED WITH CAUTION</strong> - Good ethical foundation with some areas of concern. Recommend further investigation.';
    verdictClass = 'verdict-caution';
  } else if (ethicalScore >= 40) {
    verdict = '<i class="fas fa-exclamation-triangle"></i> <strong>INVESTIGATE FURTHER</strong> - Significant red flags detected. Consider declining or negotiating major changes.';
    verdictClass = 'verdict-warning';
  } else {
    verdict = '<i class="fas fa-times-circle"></i> <strong>DO NOT JOIN</strong> - Toxic, unethical, or deceptive environment. This role is not a good fit.';
    verdictClass = 'verdict-danger';
  }

  const verdictElement = document.getElementById('results-verdict');
  verdictElement.className = 'results-verdict ' + verdictClass;
  verdictElement.innerHTML = verdict;

  // Generate encrypted verdict (SHA-256)
  const verdictText = `ROCS Assessment - Ethical: ${ethicalScore}% | Cultural Fit: ${culturalFit}% | Red Flags: ${redFlags} | Verdict: ${verdict}`;
  const encryptedVer dict = CryptoJS.SHA256(verdictText).toString();
  const encryptedTextarea = document.getElementById('encrypted-verdict');
  encryptedTextarea.value = encryptedVerdictText;

  // Show results section
  document.getElementById('assessment-results').style.display = 'block';
  document.getElementById('assessment-results').scrollIntoView({ behavior: 'smooth' });
}

// Terminal Commands Setup
function setupTerminalCommands() {
  const terminalOutput = document.getElementById('terminal-output');
  const terminalInput = document.getElementById('terminal-command');

  if (!terminalInput) return;

  const commands = {
    help: () => `Available commands:
  help              - Show this help message
  whoami            - Display current user
  vciso_services    - List vCISO services
  frameworks        - Display security frameworks
  clear             - Clear terminal output`,
    whoami: () => 'Roman Orłowski - vCISO | ROCyberSolutions',
    vciso_services: () => `vCISO Services:
  • Strategic Security Governance
  • Risk Management & Assessments
  • Compliance Framework Implementation
  • Incident Response Planning
  • Cybersecurity Awareness Training
  • Third-Party Risk Management`,
    frameworks: () => `Security Frameworks:
  • NIST Cybersecurity Framework (CSF)
  • ISO 27001 - Information Security Management
  • NIS2 - EU Cybersecurity Directive
  • GDPR - Data Protection Regulation
  • SOX - Sarbanes-Oxley Compliance
  • DORA - Digital Operational Resilience`,
    clear: () => {
      terminalOutput.innerHTML = '<div class="terminal-line"><span class="terminal-prompt">$</span> Terminal cleared</div>';
      return null;
    }
  };

  terminalInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      const cmd = this.value.trim().toLowerCase();
      this.value = '';

      // Display command
      const cmdLine = document.createElement('div');
      cmdLine.className = 'terminal-line';
      cmdLine.innerHTML = `<span class="terminal-prompt">$</span> ${cmd}`;
      terminalOutput.appendChild(cmdLine);

      // Execute command
      const result = commands[cmd] ? commands[cmd]() : `Command not found: ${cmd}`;
      if (result) {
        const resultLine = document.createElement('div');
        resultLine.className = 'terminal-line';
        resultLine.textContent = result;
        terminalOutput.appendChild(resultLine);
      }

      terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }
  });
}

// Expandable UI Setup
function setupExpandableUI() {
  const expandBtn = document.getElementById('expand-btn');
  const inventory = document.querySelector('.pip-boy-inventory');

  if (expandBtn && inventory) {
    expandBtn.addEventListener('click', function() {
      inventory.classList.toggle('expanded');
      this.innerHTML = inventory.classList.contains('expanded') 
        ? '<i class="fas fa-compress"></i>' 
        : '<i class="fas fa-expand"></i>';
    });
  }
}
