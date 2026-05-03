function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;',
        '/': '&#x2F;'
    };
    return String(text).replace(/[&<>"'/]/g, char => map[char]);
}

function sanitizeUrl(url) {
    if (!url) return '';
    try {
        const parsed = new URL(url, window.location.origin);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return '';
        }
        return parsed.href;
    } catch {
        return '';
    }
}

function validateRedirect(url) {
    if (!url) return null;
    try {
        const parsed = new URL(url, window.location.origin);
        const allowedHosts = ['id.joshattic.us', 'localhost', window.location.hostname];
        
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return null;
        }
        
        if (!allowedHosts.includes(parsed.hostname)) {
            return null;
        }
        
        return parsed.pathname + parsed.search;
    } catch {
        return null;
    }
}

function createSecureElement(tag, attributes = {}, content = '') {
    const element = document.createElement(tag);
    
    for (const [key, value] of Object.entries(attributes)) {
        if (key === 'href' || key === 'src') {
            const sanitized = sanitizeUrl(value);
            if (sanitized) {
                element.setAttribute(key, sanitized);
            }
        } else if (key === 'onclick') {
            element.addEventListener('click', value);
        } else {
            element.setAttribute(key, escapeHtml(value));
        }
    }
    
    if (content) {
        element.textContent = content;
    }
    
    return element;
}
