function getApiBaseUrl() {
  const publicUrl = process.env.NEXT_PUBLIC_API_URL;
  if (publicUrl && typeof publicUrl === 'string' && publicUrl.trim() && !publicUrl.includes('127.0.0.1') && !publicUrl.includes('localhost')) {
    return publicUrl.trim().replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined') {
    // In browser, using relative path allows Next.js rewrite proxy to forward to FastAPI seamlessly
    return '';
  }
  return process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
}

function getStoredToken() {
  if (typeof window !== 'undefined') {
    try {
      return localStorage.getItem('phishguard_auth_token');
    } catch {
      return null;
    }
  }
  return null;
}

export function setStoredToken(token) {
  if (typeof window !== 'undefined') {
    try {
      if (token) {
        localStorage.setItem('phishguard_auth_token', token);
      } else {
        localStorage.removeItem('phishguard_auth_token');
      }
    } catch {
      // ignore
    }
  }
}

function getAuthHeaders(extraHeaders = {}) {
  const headers = { ...extraHeaders };
  const token = getStoredToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export async function fetchHealth() {
  try {
    const base = getApiBaseUrl();
    const res = await fetch(`${base}/api/health`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    return { status: 'offline', error: err.message };
  }
}

export async function fetchProviderStatus() {
  try {
    const base = getApiBaseUrl();
    const res = await fetch(`${base}/api/providers/status`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    return {
      primary_provider: 'gemini',
      gemini_configured: false,
      groq_configured: false,
      fallback_ready: false,
      deterministic_fallback_ready: true,
      error: err.message
    };
  }
}

/* ------------------- AUTHENTICATION APIS ------------------- */

export async function registerUser({ name, email, password }) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
    credentials: 'include',
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    let msg = errData.detail;
    if (Array.isArray(msg)) {
      msg = msg.map(m => m.msg || JSON.stringify(m)).join(', ');
    }
    throw new Error(msg || `Registration failed (${res.status})`);
  }
  const data = await res.json();
  if (data.access_token) {
    setStoredToken(data.access_token);
  }
  return data;
}

export async function loginUser({ email, password }) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include',
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    let msg = errData.detail;
    if (Array.isArray(msg)) {
      msg = msg.map(m => m.msg || JSON.stringify(m)).join(', ');
    }
    throw new Error(msg || `Login failed (${res.status})`);
  }
  const data = await res.json();
  if (data.access_token) {
    setStoredToken(data.access_token);
  }
  return data;
}

export async function fetchCurrentUser() {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/auth/me`, {
    headers: getAuthHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      setStoredToken(null);
      return null;
    }
    throw new Error(`Failed to fetch user (${res.status})`);
  }
  return await res.json();
}

export async function logoutUser() {
  const base = getApiBaseUrl();
  try {
    await fetch(`${base}/api/auth/logout`, {
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
  } catch (err) {
    console.warn('Logout API failed:', err);
  } finally {
    setStoredToken(null);
  }
  return { message: 'Logged out' };
}

export async function changePassword({ current_password, new_password }) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/auth/password`, {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ current_password, new_password }),
    credentials: 'include',
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    let msg = errData.detail;
    if (Array.isArray(msg)) {
      msg = msg.map(m => m.msg || JSON.stringify(m)).join(', ');
    }
    throw new Error(msg || `Failed to change password (${res.status})`);
  }
  return await res.json();
}

/* ------------------- INVESTIGATION APIS ------------------- */

export async function analyzeFormData(formData) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/analyze`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
    credentials: 'include',
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Server error: ${res.status}`);
  }
  return await res.json();
}

export async function analyzeFormDataStream(formData, onEvent) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/analyze/stream`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
    credentials: 'include',
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Server error: ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';
  let finalResult = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const messages = buffer.split('\n\n');
    buffer = messages.pop() || '';

    for (const msg of messages) {
      if (!msg.trim()) continue;
      const lines = msg.split('\n');
      let eventType = 'message';
      let dataStr = '';

      for (const line of lines) {
        if (line.startsWith('event:')) {
          eventType = line.slice(6).trim();
        } else if (line.startsWith('data:')) {
          dataStr += line.slice(5).trim();
        }
      }

      if (dataStr) {
        try {
          const parsedData = JSON.parse(dataStr);
          if (eventType === 'complete' && parsedData.result) {
            finalResult = parsedData.result;
          }
          if (onEvent) {
            onEvent({ event: eventType, data: parsedData });
          }
        } catch (e) {
          console.warn('Failed to parse SSE data frame:', dataStr, e);
        }
      }
    }
  }

  if (buffer.trim()) {
    const lines = buffer.split('\n');
    let eventType = 'message';
    let dataStr = '';
    for (const line of lines) {
      if (line.startsWith('event:')) eventType = line.slice(6).trim();
      else if (line.startsWith('data:')) dataStr += line.slice(5).trim();
    }
    if (dataStr) {
      try {
        const parsedData = JSON.parse(dataStr);
        if (eventType === 'complete' && parsedData.result) finalResult = parsedData.result;
        if (onEvent) onEvent({ event: eventType, data: parsedData });
      } catch (e) {
        // ignore
      }
    }
  }

  if (!finalResult) {
    throw new Error('Analysis completed without producing a valid dossier.');
  }

  return finalResult;
}

export async function analyzeJson(payload) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/analyze/json`, {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
    credentials: 'include',
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Server error: ${res.status}`);
  }
  return await res.json();
}

export async function fetchInvestigations(filter = {}) {
  try {
    const base = getApiBaseUrl();
    const params = new URLSearchParams();
    if (filter.rating) params.append('rating', filter.rating);
    if (filter.status) params.append('status', filter.status);
    
    const url = `${base}/api/investigations?${params.toString()}`;
    const res = await fetch(url, {
      cache: 'no-store',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('Failed to fetch investigations:', err);
    return [];
  }
}

export async function fetchInvestigationById(id) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/investigations/${id}`, {
    cache: 'no-store',
    headers: getAuthHeaders(),
    credentials: 'include',
  });
  if (!res.ok) {
    throw new Error(`Investigation ${id} not found or access unauthorized.`);
  }
  return await res.json();
}

export async function fetchInvestigationTrace(id) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/investigations/${id}/trace`, {
    cache: 'no-store',
    headers: getAuthHeaders(),
    credentials: 'include',
  });
  if (!res.ok) {
    throw new Error(`Trace for ${id} not found or access unauthorized.`);
  }
  return await res.json();
}

export async function updateReviewStatus(id, status, notes = '') {
  const base = getApiBaseUrl();
  const params = new URLSearchParams({ status, notes });
  const res = await fetch(`${base}/api/investigations/${id}/review?${params.toString()}`, {
    method: 'PATCH',
    headers: getAuthHeaders(),
    credentials: 'include',
  });
  if (!res.ok) throw new Error(`Failed to update review status.`);
  return await res.json();
}

export function getExportDownloadUrl(id, format = 'json') {
  const base = getApiBaseUrl();
  return `${base}/api/investigations/${id}/export?format=${format}`;
}

export async function submitInvestigationFeedback(invId, feedbackData) {
  const base = getApiBaseUrl();
  const res = await fetch(`${base}/api/investigations/${invId}/feedback`, {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(feedbackData),
    credentials: 'include',
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to submit feedback (HTTP ${res.status}).`);
  }
  return await res.json();
}

export async function fetchInvestigationFeedback(invId) {
  const base = getApiBaseUrl();
  try {
    const res = await fetch(`${base}/api/investigations/${invId}/feedback`, {
      cache: 'no-store',
      headers: getAuthHeaders(),
      credentials: 'include',
    });
    if (!res.ok) return [];
    return await res.json();
  } catch (err) {
    console.warn('Failed to fetch investigation feedback:', err);
    return [];
  }
}


