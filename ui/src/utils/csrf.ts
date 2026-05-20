export function getCsrfToken() {
  try {
    const cookieHeader = document.cookie || '';
    if (!cookieHeader) return '';
    const parts = cookieHeader.split(';');
    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex === -1) continue;
      const key = trimmed.slice(0, eqIndex).trim();
      if (key !== 'csrf_token') continue;
      return decodeURIComponent(trimmed.slice(eqIndex + 1).trim());
    }
  } catch {
    return '';
  }
  return '';
}

export function withCsrfHeaders(headers: HeadersInit = {}): HeadersInit {
  const token = getCsrfToken();
  if (!token) return headers;
  const next = new Headers(headers);
  next.set('X-CSRF-Token', token);
  return next;
}
