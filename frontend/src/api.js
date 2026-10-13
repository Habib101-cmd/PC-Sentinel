const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const TOKEN_KEY = "pc-sentinel-token";

export const getToken = () => sessionStorage.getItem(TOKEN_KEY) || "";
const setToken = (token) => sessionStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => sessionStorage.removeItem(TOKEN_KEY);

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (auth) headers.Authorization = `Bearer ${getToken()}`;

  let response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Serveur injoignable.", 0);
  }

  if (!response.ok) {
    let detail = "Une erreur est survenue.";
    try {
      const data = await response.json();
      if (typeof data.detail === "string") detail = data.detail;
      else if (Array.isArray(data.detail)) detail = "Données invalides.";
    } catch {
      /* réponse sans JSON */
    }
    throw new ApiError(detail, response.status);
  }

  return response.status === 204 ? null : response.json();
}

export const register = (username, password) =>
  request("/auth/register", {
    method: "POST",
    body: { username, password },
    auth: false,
  });

export async function login(username, password) {
  const data = await request("/auth/login", {
    method: "POST",
    body: { username, password },
    auth: false,
  });
  setToken(data.access_token);
}

export const listAudits = () => request("/audits");
export const deleteAudit = (id) =>
  request(`/audits/${id}`, { method: "DELETE" });
export const deleteAccount = () => request("/users/me", { method: "DELETE" });
