/**
 * Phishing Detection Suite - Web Application
 * Main JavaScript File
 */

// Email Detector
document.getElementById('emailForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const emailContent = document.getElementById('emailContent').value;
    const emailHeaders = document.getElementById('emailHeaders').value;

    if (!emailContent.trim()) {
        showEmailError('Please enter email content');
        return;
    }

    // Show loading
    document.getElementById('emailLoading').classList.remove('hidden');
    document.getElementById('emailResults').classList.add('hidden');
    document.getElementById('emailError').classList.add('hidden');

    try {
        const response = await fetch('/api/analyze-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email_content: emailContent,
                email_headers: parseHeaders(emailHeaders)
            })
        });

        const data = await response.json();

        if (data.status === 'success') {
            displayEmailResults(data);
        } else {
            showEmailError(data.error || 'Analysis failed');
        }
    } catch (error) {
        showEmailError(error.message);
    } finally {
        document.getElementById('emailLoading').classList.add('hidden');
    }
});

function parseHeaders(headerString) {
    const headers = {};
    if (!headerString) return headers;
    
    headerString.split('\n').forEach(line => {
        const [key, value] = line.split(':');
        if (key && value) {
            headers[key.trim()] = value.trim();
        }
    });
    return headers;
}

function displayEmailResults(data) {
    const isPhishing = data.prediction === 'PHISHING';
    const confidence = Math.max(0, Math.min(100, data.confidence_numeric * 100));

    // Alert
    const alertDiv = document.getElementById('emailThreatAlert');
    const threatTitle = document.getElementById('emailThreatTitle');
    const threatMessage = document.getElementById('emailThreatMessage');

    if (isPhishing) {
        alertDiv.className = 'alert alert-danger';
        threatTitle.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> PHISHING DETECTED';
        threatMessage.textContent = 'This email appears to be a phishing attempt. Do not click links or provide information.';
    } else {
        alertDiv.className = 'alert alert-success';
        threatTitle.innerHTML = '<i class="bi bi-check-circle-fill"></i> EMAIL APPEARS LEGITIMATE';
        threatMessage.textContent = 'This email appears to be safe, but always verify sender information.';
    }

    // Confidence Bar
    const confBar = document.getElementById('emailConfidenceBar');
    confBar.style.width = confidence + '%';
    confBar.className = 'progress-bar progress-bar-striped progress-bar-animated ' + (isPhishing ? 'bg-danger' : 'bg-success');
    document.getElementById('emailConfidenceText').textContent = confidence.toFixed(1) + '%';

    // Language Detection
    const lang = data.language;
    const mlPhishing = data.multilingual_phishing;
    
    let languageHTML = `
        <div class="row g-2">
            <div class="col-md-6">
                <strong><i class="bi bi-translate"></i> Primary Language:</strong>
                <span class="badge bg-primary">${lang.primary.toUpperCase()}</span>
                <span class="text-muted small">(${(lang.confidence * 100).toFixed(1)}%)</span>
            </div>
            <div class="col-md-6">
                <strong><i class="bi bi-globe2"></i> Multilingual:</strong>
                <span class="badge ${lang.is_multilingual ? 'bg-warning text-dark' : 'bg-secondary'}">${lang.is_multilingual ? 'YES' : 'NO'}</span>
            </div>
        </div>
    `;
    
    if (lang.is_multilingual) {
        languageHTML += `
            <div class="mt-2">
                <small class="text-muted">Languages detected: ${lang.all_detected.join(', ')}</small>
            </div>
        `;
    }
    
    if (mlPhishing.detected) {
        languageHTML += `
            <div class="mt-3">
                <strong><i class="bi bi-exclamation-octagon"></i> Phishing Keywords Found:</strong>
                <span class="badge bg-danger">${mlPhishing.keyword_count}</span>
                <div class="mt-2">
                    <small class="text-muted">Keywords: ${getKeywordDisplay(mlPhishing.keywords, 8).join(', ')}</small>
                </div>
            </div>
        `;
        
        if (mlPhishing.risk_multiplier > 1.0) {
            languageHTML += `
                <div class="mt-2">
                    <strong><i class="bi bi-shield-exclamation"></i> Risk Multiplier:</strong>
                    <span class="badge bg-danger">${mlPhishing.risk_multiplier.toFixed(2)}x</span>
                </div>
            `;
        }
    }
    
    if (data.translation && data.translation.needed) {
        languageHTML += `
            <div class="mt-2">
                <span class="badge bg-info"><i class="bi bi-arrow-left-right"></i> Translation Available</span>
            </div>
        `;
    }
    
    document.getElementById('emailLanguageDetails').innerHTML = languageHTML;

    // Authentication Details
    const authDetails = document.getElementById('emailAuthDetails');
    authDetails.innerHTML = `
        <li><strong>SPF:</strong> <span class="badge bg-${data.features.spf_pass ? 'success' : 'danger'}">
            ${data.features.spf_pass ? 'PASS' : 'FAIL'}</span></li>
        <li><strong>DKIM:</strong> <span class="badge bg-${data.features.dkim_pass ? 'success' : 'danger'}">
            ${data.features.dkim_pass ? 'PASS' : 'FAIL'}</span></li>
        <li><strong>DMARC:</strong> <span class="badge bg-${data.features.dmarc_pass ? 'success' : 'danger'}">
            ${data.features.dmarc_pass ? 'PASS' : 'FAIL'}</span></li>
    `;

    // Content Details
    const contentDetails = document.getElementById('emailContentDetails');
    contentDetails.innerHTML = `
        <li><strong>URLs:</strong> ${data.features.url_count}</li>
        <li><strong>Shortener URLs:</strong> ${data.features.has_shortener ? 'Yes ⚠️' : 'No'}</li>
        <li><strong>Suspicious Keywords:</strong> ${data.features.suspicious_keywords}</li>
        <li><strong>Urgency Score:</strong> ${data.features.urgency_score}</li>
    `;

    // Recommendation
    document.getElementById('emailRecommendation').textContent = data.recommendation;

    // Show results
    document.getElementById('emailResults').classList.remove('hidden');
}

function getKeywordDisplay(keywords, limit = 5) {
    if (!keywords || keywords.length === 0) return [];
    
    const display = [];
    for (let i = 0; i < Math.min(keywords.length, limit); i++) {
        const kw = keywords[i];
        if (typeof kw === 'object') {
            display.push(kw.keyword || JSON.stringify(kw));
        } else {
            display.push(kw);
        }
    }
    return display;
}

function showEmailError(message) {
    const errorDiv = document.getElementById('emailError');
    errorDiv.textContent = 'Error: ' + message;
    errorDiv.classList.remove('hidden');
}

// File Analyzer
document.getElementById('fileForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!file) {
        showFileError('Please select a file');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    document.getElementById('fileLoading').classList.remove('hidden');
    document.getElementById('fileResults').classList.add('hidden');
    document.getElementById('fileError').classList.add('hidden');

    try {
        const response = await fetch('/api/analyze-file', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.status === 'success') {
            displayFileResults(data);
        } else {
            showFileError(data.error || 'Analysis failed');
        }
    } catch (error) {
        showFileError(error.message);
    } finally {
        document.getElementById('fileLoading').classList.add('hidden');
    }
});

function displayFileResults(data) {
    const isMalicious = data.prediction === 'MALICIOUS';
    const confidence = Math.max(0, Math.min(100, data.confidence_numeric * 100));

    // Alert
    const alertDiv = document.getElementById('fileThreatAlert');
    const threatTitle = document.getElementById('fileThreatTitle');
    const threatMessage = document.getElementById('fileThreatMessage');

    if (isMalicious) {
        alertDiv.className = 'alert alert-danger';
        threatTitle.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> MALWARE DETECTED';
        threatMessage.textContent = 'This file appears to contain malicious code. Do not execute or open.';
    } else {
        alertDiv.className = 'alert alert-success';
        threatTitle.innerHTML = '<i class="bi bi-check-circle-fill"></i> FILE APPEARS SAFE';
        threatMessage.textContent = 'This file appears to be benign, but always be cautious with unknown files.';
    }

    // Filename
    document.getElementById('filename').textContent = data.filename;

    // Confidence
    const confBar = document.getElementById('fileConfidenceBar');
    confBar.style.width = confidence + '%';
    confBar.className = 'progress-bar progress-bar-striped progress-bar-animated ' + (isMalicious ? 'bg-danger' : 'bg-success');
    document.getElementById('fileConfidenceText').textContent = confidence.toFixed(1) + '%';

    // Hashes
    document.getElementById('hashMD5').textContent = data.hashes.md5;
    document.getElementById('hashSHA1').textContent = data.hashes.sha1;
    document.getElementById('hashSHA256').textContent = data.hashes.sha256;

    // Features
    document.getElementById('entropy').textContent = data.features.entropy;
    document.getElementById('peHeader').innerHTML = 
        `<span class="badge bg-${data.features.has_pe_header ? 'warning' : 'success'}">
            ${data.features.has_pe_header ? 'YES' : 'NO'}</span>`;
    document.getElementById('elfHeader').innerHTML = 
        `<span class="badge bg-${data.features.has_elf_header ? 'warning' : 'success'}">
            ${data.features.has_elf_header ? 'YES' : 'NO'}</span>`;
    document.getElementById('suspiciousStrings').textContent = data.features.suspicious_strings;

    // Recommendation
    document.getElementById('fileRecommendation').textContent = data.recommendation;

    document.getElementById('fileResults').classList.remove('hidden');
}

function showFileError(message) {
    const errorDiv = document.getElementById('fileError');
    errorDiv.textContent = 'Error: ' + message;
    errorDiv.classList.remove('hidden');
}

// Console welcome message
console.log('%c🛡️ Phishing Detection Suite', 'font-size: 20px; font-weight: bold; color: #007bff;');
console.log('%cWeb Application v2.0 | Multilingual Detection Enabled', 'font-size: 12px; color: #6c757d;');
console.log('%cSupported Languages: English, Vietnamese, Chinese', 'font-size: 11px; color: #28a745;');
