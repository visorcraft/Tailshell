(function () {
  const form = document.getElementById('inviteForm');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const metaDiv = document.getElementById('meta');
  const submitBtn = document.getElementById('submitBtn');

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
    showError('Missing invite token.');
    submitBtn.disabled = true;
    return;
  }

  (async () => {
    try {
      const resp = await fetch(`/api/invites/${encodeURIComponent(token)}`);
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || !data.valid) {
        showError(data.error || 'Invite is invalid or expired.');
        submitBtn.disabled = true;
        return;
      }
      const role = data.role || 'user';
      metaDiv.textContent = `Role: ${role}`;
    } catch {
      showError('Connection error. Please try again.');
      submitBtn.disabled = true;
    }
  })();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    successDiv.classList.remove('visible');

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!username || !password || !confirmPassword) {
      showError('All fields are required.');
      return;
    }
    if (password.length < 8) {
      showError('Password must be at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      showError('Passwords do not match.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating...';

    try {
      const resp = await fetch(`/api/invites/${encodeURIComponent(token)}/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await resp.json().catch(() => ({}));

      if (!resp.ok) {
        showError(data.error || 'Invite failed.');
        return;
      }

      try {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('tokenExpires');
      } catch {
        // ignore
      }

      showSuccess('Account created. Redirecting…');
      setTimeout(() => {
        window.location.href = '/';
      }, 700);
    } catch {
      showError('Connection error. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create account';
    }
  });
})();

