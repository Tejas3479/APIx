/* APIx shared application helpers.
 *
 * Loaded on every page before each page's inline script. Keeps the common
 * utilities (formatting, escaping, auth headers, animations) in one place.
 */

/* Format a number as Indian Rupees (₹1,23,456.00). */
function formatINR(val, includeDecimals = false) {
  if (val === null || val === undefined || isNaN(val)) return 'N/A';
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: includeDecimals ? 2 : 0,
    minimumFractionDigits: includeDecimals ? 2 : 0,
  }).format(val);
}

/* Escape a string for safe insertion into HTML. */
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* Alias for brevity */
function esc(str) {
  return escapeHtml(str);
}

/* Build fetch headers, attaching stored JWT when present. */
function authHeaders(extra = {}) {
  const headers = { ...extra };
  const token = localStorage.getItem('apix_token');
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return headers;
}

/* Read cached officer / analyst identity object. */
function getCachedOfficer() {
  try {
    const raw = localStorage.getItem('apix_officer');
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

/* Price count-up animation for fare displays. */
function animatePriceCount(el, targetPrice, duration = 800) {
  if (!el) return;
  const startTime = performance.now();
  const startPrice = 0;

  function animate(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(startPrice + (targetPrice - startPrice) * eased);
    el.textContent = formatINR(current);
    if (progress < 1) requestAnimationFrame(animate);
  }
  requestAnimationFrame(animate);
}

/* Decimal count-up animation for APIx index points (e.g. 103.7). */
function animateIndex(el, targetIndex, decimals = 1, duration = 800) {
  if (!el) return;
  const startTime = performance.now();
  const startVal = 100.0;

  function animate(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = (startVal + (targetIndex - startVal) * eased).toFixed(decimals);
    el.textContent = current;
    if (progress < 1) requestAnimationFrame(animate);
  }
  requestAnimationFrame(animate);
}

/* Ensure a valid JWT session exists before protected API calls. */
async function ensureAuth() {
  const token = localStorage.getItem('apix_token');
  if (token) {
    try {
      const res = await fetch('/auth/me', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (res.ok) {
        const profile = await res.json();
        const officer = {
          name: profile.name,
          dept: profile.department || 'National Statistical Office (MoSPI)',
          role: profile.role || 'Price Index Compiler',
          email: profile.email || 'sk.mukherjee@mospi.gov.in'
        };
        localStorage.setItem('apix_officer', JSON.stringify(officer));
        return officer;
      }
    } catch (e) {
      // Network error — fall through to demo-login
    }
    localStorage.removeItem('apix_token');
  }

  try {
    const res = await fetch('/auth/demo-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Dr. S. K. Mukherjee',
        email: 'sk.mukherjee@mospi.gov.in',
        department: 'National Statistical Office (Price Statistics)',
        role: 'senior_officer'
      })
    });
    if (!res.ok) return null;
    const body = await res.json();
    localStorage.setItem('apix_token', body.access_token);
    const officer = {
      name: 'Dr. S. K. Mukherjee',
      dept: 'National Statistical Office (Price Statistics)',
      role: 'Senior Statistical Officer',
      email: 'sk.mukherjee@mospi.gov.in'
    };
    localStorage.setItem('apix_officer', JSON.stringify(officer));
    return officer;
  } catch (e) {
    return null;
  }
}

/* Integer count-up animation for integer metrics. */
function animateInteger(el, targetInt, duration = 800) {
  if (!el) return;
  const startTime = performance.now();
  const startVal = 0;

  function animate(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(startVal + (targetInt - startVal) * eased);
    el.textContent = current.toLocaleString('en-IN');
    if (progress < 1) requestAnimationFrame(animate);
  }
  requestAnimationFrame(animate);
}

/* Modern floating toast notification system. */
function showToast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast-card toast-${type} toast-enter`;

  const icon = type === 'success' ? '✓' :
               type === 'warning' ? '⚠' :
               type === 'error' ? '✕' : 'ℹ';

  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-body">${escapeHtml(message)}</div>
    <button class="toast-close" onclick="this.parentElement.remove()" aria-label="Close">×</button>
  `;

  container.appendChild(toast);

  // Auto remove
  setTimeout(() => {
    toast.classList.remove('toast-enter');
    toast.classList.add('toast-exit');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/* Copy text to clipboard with modern toast feedback. */
async function copyToClipboard(text, successMsg = 'Copied to clipboard!') {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    showToast(successMsg, 'success');
  } catch (err) {
    showToast('Failed to copy: ' + err.message, 'error');
  }
}

