'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
let csrfToken    = '';   // fetched once on page load, refreshed as needed
let sessionId    = null;
let totalExpiry  = 250;
let cdInterval   = null;
let barInterval  = null;

// ─── Boot: fetch CSRF token immediately on page load ─────────────────────────
(async function boot() {
  try {
    const res  = await fetch('/auth/csrf-token', { credentials: 'include' });
    const data = await res.json();
    csrfToken  = data.csrfToken || '';
    if (!csrfToken) console.warn('CSRF token empty on boot');
  } catch (e) {
    console.error('Could not fetch CSRF token:', e);
  }
})();

async function refreshCsrf() {
  try {
    const res  = await fetch('/auth/csrf-token', { credentials: 'include' });
    const data = await res.json();
    csrfToken  = data.csrfToken || '';
  } catch {}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function $(id) { return document.getElementById(id); }

function showError(wrapId, textId, msg) {
  $(textId).textContent = msg;
  $(wrapId).classList.remove('hidden');
}
function hideError(id) { $(id).classList.add('hidden'); }

function setLoading(btnId, spinnerId, textId, state, label) {
  $(btnId).disabled = state;
  $(spinnerId).classList.toggle('hidden', !state);
  if (label) $(textId).textContent = state ? 'Please wait…' : label;
}

function isValidEmail(e) {
  // Accepts any RFC-5322-like address: user@domain.tld
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e.trim());
}

// ─── Request login ────────────────────────────────────────────────────────────
async function requestLogin() {
  const emailEl = $('email');
  const email   = (emailEl.value || '').trim();

  hideError('error-msg');

  if (!email) {
    showError('error-msg', 'error-msg-text', 'Please enter your email address.');
    emailEl.focus();
    return;
  }
  if (!isValidEmail(email)) {
    showError('error-msg', 'error-msg-text', 'Enter a valid email — e.g. yourname@gmail.com');
    emailEl.focus();
    return;
  }

  setLoading('btn-request', 'btn-spinner', 'btn-text', true, 'Send login link');

  // Always get a fresh CSRF token right before posting
  await refreshCsrf();

  if (!csrfToken) {
    showError('error-msg', 'error-msg-text', 'Security token missing. Please refresh the page.');
    setLoading('btn-request', 'btn-spinner', 'btn-text', false, 'Send login link');
    return;
  }

  try {
    const res  = await fetch('/auth/request', {
      method:      'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ email }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError('error-msg', 'error-msg-text', data.error || 'Failed to send email. Try again.');
      return;
    }

    // Success
    sessionId   = data.sessionId;
    totalExpiry = data.expiresIn || 250;

    $('sent-email').textContent = email;
    $('step-email').classList.add('hidden');
    const otpStep = $('step-otp');
    otpStep.classList.remove('hidden');
    otpStep.classList.add('step-enter');

    startProgressBar(totalExpiry);
    startCountdown(totalExpiry);
    focusFirstBox();

  } catch (err) {
    showError('error-msg', 'error-msg-text', 'Network error. Check your connection and try again.');
  } finally {
    setLoading('btn-request', 'btn-spinner', 'btn-text', false, 'Send login link');
  }
}

// ─── Top progress bar ─────────────────────────────────────────────────────────
function startProgressBar(seconds) {
  if (barInterval) clearInterval(barInterval);

  const wrap = $('progress-bar-wrap');
  const fill = $('progress-bar-fill');

  wrap.style.display = 'block';
  fill.style.transition = 'none';
  fill.style.width = '100%';

  let elapsed = 0;
  barInterval = setInterval(() => {
    elapsed++;
    const pct = Math.max(0, ((seconds - elapsed) / seconds) * 100);
    fill.style.transition = 'width 1s linear';
    fill.style.width = pct + '%';
    if (elapsed >= seconds) {
      clearInterval(barInterval);
      barInterval = null;
    }
  }, 1000);
}

// ─── Countdown ring ───────────────────────────────────────────────────────────
function startCountdown(seconds) {
  if (cdInterval) clearInterval(cdInterval);

  const numEl    = $('countdown-number');
  const ringEl   = $('ring-circle');
  const labelEl  = $('countdown-label');
  const resendRow = $('resend-row');
  const verifyBtn = $('btn-verify');

  const circumference = 188.5;
  let remaining = seconds;

  function tick() {
    numEl.textContent = remaining;
    const offset = circumference * (1 - remaining / seconds);
    ringEl.setAttribute('stroke-dashoffset', offset.toString());
    if (remaining <= 30) ringEl.classList.add('expiring');
    if (remaining <= 0)  ringEl.classList.add('expired');
  }

  tick();

  cdInterval = setInterval(() => {
    remaining--;
    tick();
    if (remaining <= 0) {
      clearInterval(cdInterval);
      cdInterval = null;
      labelEl.textContent = 'Expired — request a new link';
      resendRow.classList.remove('hidden');
      verifyBtn.disabled = true;
    }
  }, 1000);
}

// ─── OTP box wiring ───────────────────────────────────────────────────────────
function focusFirstBox() {
  const boxes = document.querySelectorAll('.otp-box');
  if (boxes.length) boxes[0].focus();
}

function getOtp() {
  return [...document.querySelectorAll('.otp-box')].map(b => b.value).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  const boxes = [...document.querySelectorAll('.otp-box')];

  boxes.forEach((box, i) => {
    box.addEventListener('input', e => {
      const val = e.target.value.replace(/\D/g, '');
      e.target.value = val ? val[val.length - 1] : '';
      e.target.classList.toggle('filled', !!e.target.value);
      if (val && i < boxes.length - 1) boxes[i + 1].focus();
      if (getOtp().length === 8) verifyOtp();
    });

    box.addEventListener('keydown', e => {
      if (e.key === 'Backspace') {
        if (!e.target.value && i > 0) {
          boxes[i - 1].value = '';
          boxes[i - 1].classList.remove('filled');
          boxes[i - 1].focus();
        }
        e.target.classList.remove('filled');
      }
      if (e.key === 'Enter')      verifyOtp();
      if (e.key === 'ArrowLeft'  && i > 0)            boxes[i - 1].focus();
      if (e.key === 'ArrowRight' && i < boxes.length-1) boxes[i + 1].focus();
    });

    box.addEventListener('paste', e => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData)
        .getData('text').replace(/\D/g, '').slice(0, 8);
      pasted.split('').forEach((ch, j) => {
        if (boxes[j]) { boxes[j].value = ch; boxes[j].classList.add('filled'); }
      });
      boxes[Math.min(pasted.length, boxes.length - 1)].focus();
      if (pasted.length === 8) verifyOtp();
    });
  });

  // Enter on email field
  const emailEl = $('email');
  if (emailEl) emailEl.addEventListener('keydown', e => { if (e.key === 'Enter') requestLogin(); });
});

// ─── Verify OTP ───────────────────────────────────────────────────────────────
async function verifyOtp() {
  const otp = getOtp();
  hideError('otp-error');

  if (!/^\d{8}$/.test(otp)) {
    showError('otp-error', 'otp-error-text', 'Enter all 8 digits of your code.');
    return;
  }
  if (!sessionId) {
    showError('otp-error', 'otp-error-text', 'Session lost. Request a new login link.');
    return;
  }

  setLoading('btn-verify', 'verify-spinner', 'verify-text', true, 'Verify code');
  await refreshCsrf();

  try {
    const res  = await fetch('/auth/verify-otp', {
      method:      'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ sessionId, otp }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError('otp-error', 'otp-error-text', data.error || 'Verification failed.');
      document.querySelectorAll('.otp-box').forEach(b => {
        b.value = '';
        b.classList.remove('filled');
      });
      focusFirstBox();
      return;
    }

    // Success — stop timers and go to dashboard
    if (cdInterval)  clearInterval(cdInterval);
    if (barInterval) clearInterval(barInterval);
    $('progress-bar-wrap').style.display = 'none';
    window.location.href = '/dashboard';

  } catch {
    showError('otp-error', 'otp-error-text', 'Network error. Try again.');
  } finally {
    setLoading('btn-verify', 'verify-spinner', 'verify-text', false, 'Verify code');
  }
}

// ─── Reset ────────────────────────────────────────────────────────────────────
function resetToEmail() {
  if (cdInterval)  clearInterval(cdInterval);
  if (barInterval) clearInterval(barInterval);
  $('progress-bar-wrap').style.display = 'none';
  sessionId = null;

  $('step-otp').classList.add('hidden');
  $('step-email').classList.remove('hidden');
  document.querySelectorAll('.otp-box').forEach(b => {
    b.value = '';
    b.classList.remove('filled');
  });
  hideError('otp-error');
  hideError('error-msg');
  $('resend-row').classList.add('hidden');
  $('btn-verify').disabled = false;
  $('countdown-label').textContent = 'seconds remaining';
  $('ring-circle').classList.remove('expiring', 'expired');
  $('email').focus();
}
