(function () {
  const form = document.getElementById('resetPasswordForm');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const submitBtn = document.getElementById('submitBtn');
  const subtitle = document.getElementById('subtitle');

  function showError(message) {
    successDiv.classList.remove('visible');
    errorDiv.textContent = message;
    errorDiv.classList.add('visible');
  }

  function showSuccess(message) {
    errorDiv.classList.remove('visible');
    successDiv.textContent = message;
    successDiv.classList.add('visible');
  }

  function getToken() {
    try {
      const params = new URLSearchParams(window.location.search);
      return (params.get('token') || '').trim();
    } catch {
      return '';
    }
  }

  const token = getToken();
  if (!token) {
    showError('Missing reset token.');
    submitBtn.disabled = true;
    return;
  }

  (async () => {
    try {
      const resp = await fetch(`/api/password-resets/${encodeURIComponent(token)}`);
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || !data.valid) {
        showError(data.error || 'Reset is invalid or expired.');
        submitBtn.disabled = true;
        return;
      }
      const username = data.username || '';
      if (username) subtitle.textContent = `Reset password for ${username}.`;
    } catch {
      showError('Connection error. Please try again.');
      submitBtn.disabled = true;
    }
  })();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    successDiv.classList.remove('visible');

    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!newPassword || !confirmPassword) {
      showError('All fields are required.');
      return;
    }

    if (newPassword.length < 8) {
      showError('New password must be at least 8 characters.');
      return;
    }

    if (newPassword !== confirmPassword) {
      showError('New passwords do not match.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Resetting...';

    try {
      const resp = await fetch(`/api/password-resets/${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ newPassword })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        showError(data.error || 'Failed to reset password.');
        return;
      }

      try {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('tokenExpires');
      } catch {
        // ignore
      }

      showSuccess('Password reset. Redirecting…');
      setTimeout(() => {
        window.location.href = '/';
      }, 700);
    } catch {
      showError('Connection error. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Reset password';
    }
  });
})();

