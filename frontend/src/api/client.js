const TOKEN_STORAGE_KEY = 'sg_operator_bearer_v1';

let memoryBearerToken = '';

export function getStoredBearerToken() {
  if (memoryBearerToken) return memoryBearerToken;
  try {
    const val = window.sessionStorage.getItem(TOKEN_STORAGE_KEY) || '';
    if (val) memoryBearerToken = val;
    return val;
  } catch {
    return '';
  }
}

export function setStoredBearerToken(token) {
  memoryBearerToken = token || '';
  try {
    if (token) {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage unavailability
  }
}

async function parseJsonSafe(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

async function apiRequest(path, { method = 'GET', body = null, authRequired = true } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== null) {
    headers['Content-Type'] = 'application/json';
  }
  if (authRequired) {
    const token = getStoredBearerToken();
    if (!token) {
      const err = new Error('Operator session token missing');
      err.code = 'UNAUTHENTICATED';
      err.status = 401;
      throw err;
    }
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(path, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
    cache: 'no-store'
  });

  const data = await parseJsonSafe(res);
  if (!res.ok) {
    const err = new Error(data?.error?.message || `Request failed (${res.status})`);
    err.code = data?.error?.code || 'REQUEST_FAILED';
    err.status = res.status;
    if (res.status === 401 && authRequired) {
      setStoredBearerToken('');
    }
    throw err;
  }

  return data;
}

export async function fetchBootstrapStatus() {
  return apiRequest('/bff/bootstrap', { authRequired: false });
}

export async function verifyExistingSession() {
  if (!getStoredBearerToken()) return null;
  try {
    return await apiRequest('/bff/auth/session', { authRequired: true });
  } catch {
    setStoredBearerToken('');
    return null;
  }
}

export async function loginOperator({ username, password }) {
  const data = await apiRequest('/bff/auth/login', {
    method: 'POST',
    body: { username, password },
    authRequired: false
  });
  if (data?.token) {
    setStoredBearerToken(data.token);
  }
  return data;
}

export async function logoutOperator() {
  try {
    await apiRequest('/bff/auth/logout', { method: 'POST', authRequired: Boolean(getStoredBearerToken()) });
  } catch {
    // Clear local session regardless
  } finally {
    setStoredBearerToken('');
  }
}

export async function listEvents({ limit = 100, offset = 0 } = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset)
  });
  return apiRequest(`/bff/api/v1/events?${params.toString()}`);
}

export async function getEventById(requestId) {
  return apiRequest(`/bff/api/v1/events/${encodeURIComponent(requestId)}`);
}

export async function patchEvent(requestId, updates) {
  return apiRequest(`/bff/api/v1/events/${encodeURIComponent(requestId)}`, {
    method: 'PATCH',
    body: updates
  });
}

export async function deleteEvent(requestId, { archive = false } = {}) {
  const suffix = archive ? '?archive=true' : '';
  return apiRequest(`/bff/api/v1/events/${encodeURIComponent(requestId)}${suffix}`, {
    method: 'DELETE'
  });
}
