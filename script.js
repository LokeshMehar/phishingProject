// DOM Elements
const textInput = document.getElementById('textInput');
const modal = document.getElementById('resultModal');
const modalTitle = document.getElementById('modalTitle');
const modalMessage = document.getElementById('modalMessage');

function switchTab(tab) {
    if (tab === 'dashboard') {
        showModal('Info', 'You are already on the Dashboard view.', false, 'status-info');
    } else if (tab === 'scanner') {
        document.getElementById('textInput').focus();
    }
}

// Load a sample phishing URL for demonstration
function loadSampleText() {
    textInput.value = "URGENT: Your account has been suspended. Click here to verify your identity: http://secure-login-update.com/verify";
}

// Simulated Analysis Function for Text
function analyzeText() {
    const text = textInput.value.trim().toLowerCase();
    
    if (!text) {
        showModal('Error', 'Please enter some text, a link, or an SMS message to analyze.', false, 'status-danger');
        return;
    }

    let isScam = false;
    let message = 'No threats detected. The text appears safe.';
    
    // 1. Strict Email Detection: Only @gmail.com is original
    const emailPattern = /[a-z0-9_\.-]+@([a-z0-9\.-]+)/i;
    const emailMatch = text.match(emailPattern);
    if (!isScam && emailMatch) {
        const domain = emailMatch[1].toLowerCase();
        if (domain !== 'gmail.com') {
            isScam = true;
            message = `Phishing Alert: Detected a fake email domain (@${domain}). Only @gmail.com is considered original.`;
        }
    }

    // 2. Fake SMS Keyword Detection
    const scamKeywords = [
        'kyc suspended', 'bank account blocked', 'electricity bill', 
        'power will be disconnected', 'dear customer', 'lottery', 
        'prize', 'claim reward', 'free-gift', 'urgent verify'
    ];
    if (!isScam) {
        for (const keyword of scamKeywords) {
            if (text.includes(keyword)) {
                isScam = true;
                message = `Scam Alert: Contains common fake SMS keyword ("${keyword}").`;
                break;
            }
        }
    }

    // 3. Custom URLs are fake
    // Matches any http/https link or domain/path pattern
    const urlPattern = /(https?:\/\/[^\s]+|[a-z0-9.-]+\.[a-z]{2,4}\/[^\s]*)/i;
    if (!isScam && urlPattern.test(text)) {
        isScam = true;
        message = 'Phishing Alert: SMS or text containing custom URLs are fake. Do not click the link.';
    }

    showModal(
        isScam ? 'Threat Detected' : 'Scan Complete - Safe',
        message,
        isScam,
        isScam ? 'status-danger' : 'status-success'
    );
}

// Modal Logic
function showModal(title, message, isDanger, titleClass) {
    modalTitle.textContent = title;
    modalMessage.textContent = message;
    
    // Clear old classes
    modalTitle.className = '';
    if (titleClass) {
        modalTitle.classList.add(titleClass);
    }
    
    modal.classList.add('active');
}

function closeModal() {
    modal.classList.remove('active');
}

// Close modal when clicking outside
modal.addEventListener('click', (e) => {
    if (e.target === modal) {
        closeModal();
    }
});
