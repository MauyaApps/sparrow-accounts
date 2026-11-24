import { client, ready } from "../../src/opaque.js";
import "./style.css";

interface Account {
  id: string;
  username: string;
  status: "active" | "suspended" | "banned";
  createdAt: number;
  updatedAt: number;
}

interface AccountSession {
  id: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  revokedAt: number | null;
  userAgent: string | null;
}

interface ApiFailure {
  error?: { message?: string };
}

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing page element: ${id}`);
  return element as T;
};

const loginView = byId<HTMLElement>("login-view");
const appView = byId<HTMLElement>("app-view");
const loginError = byId<HTMLElement>("login-error");
const flash = byId<HTMLElement>("flash");
const accountBody = byId<HTMLTableSectionElement>("accounts-body");
const emptyState = byId<HTMLElement>("empty-state");
const sessionsPanel = byId<HTMLElement>("sessions-panel");
const sessionsContent = byId<HTMLElement>("sessions-content");
let currentPage = 1;
let visibleCount = 0;
let hasNextPage = false;
let selectedAccount: Account | null = null;
let searchTimer: number | undefined;

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
    credentials: "same-origin",
  });
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const failure = payload as ApiFailure | null;
    throw new Error(failure?.error?.message ?? `Request failed (${response.status})`);
  }
  return payload as T;
}

function showFlash(message: string, isError = false): void {
  flash.textContent = message;
  flash.className = isError ? "message error visible" : "message success visible";
  window.setTimeout(() => {
    flash.textContent = "";
    flash.className = "message";
  }, 5000);
}

function formatDate(seconds: number): string {
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" }).format(new Date(seconds * 1000));
}

function statusLabel(status: Account["status"]): string {
  return status === "active" ? "Активен" : status === "suspended" ? "Приостановлен" : "Заблокирован";
}

function statusClass(status: Account["status"]): string {
  return status === "active" ? "active" : status === "suspended" ? "suspended" : "banned";
}

async function loadAccounts(): Promise<void> {
  const query = new URLSearchParams({
    page: String(currentPage),
    q: byId<HTMLInputElement>("search-input").value.trim(),
    status: byId<HTMLSelectElement>("status-filter").value,
  });
  const result = await api<{ accounts: Account[]; page: number; pageSize: number; hasMore: boolean }>(`/admin/api/accounts?${query}`);
  accountBody.replaceChildren();
  visibleCount = result.accounts.length;
  hasNextPage = result.hasMore;
  byId<HTMLElement>("account-count").textContent = String(visibleCount);
  byId<HTMLElement>("page-label").textContent = `Страница ${result.page}`;
  byId<HTMLButtonElement>("prev-page").disabled = currentPage <= 1;
  byId<HTMLButtonElement>("next-page").disabled = !hasNextPage;
  emptyState.hidden = visibleCount !== 0;
  for (const account of result.accounts) accountBody.append(makeAccountRow(account));
}

function makeAccountRow(account: Account): HTMLTableRowElement {
  const row = document.createElement("tr");
  row.className = "account-row";

  const identity = document.createElement("td");
  identity.className = "identity-cell";
  const avatar = document.createElement("span");
  avatar.className = "avatar";
  avatar.textContent = account.username.slice(0, 1).toUpperCase();
  const identityText = document.createElement("span");
  identityText.className = "identity-text";
  const username = document.createElement("strong");
  username.textContent = account.username;
  const id = document.createElement("small");
  id.textContent = account.id;
  identityText.append(username, id);
  identity.append(avatar, identityText);

  const created = document.createElement("td");
  created.className = "date-cell";
  created.textContent = formatDate(account.createdAt);

  const statusCell = document.createElement("td");
  const status = document.createElement("span");
  status.className = `status-pill ${statusClass(account.status)}`;
  const statusDot = document.createElement("span");
  statusDot.className = "status-dot";
  status.append(statusDot, document.createTextNode(statusLabel(account.status)));
  statusCell.append(status);

  const actions = document.createElement("td");
  actions.className = "actions-cell";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "text-button";
  edit.textContent = "Имя";
  edit.addEventListener("click", () => void editUsername(account));
  const state = document.createElement("select");
  state.className = "status-select";
  state.setAttribute("aria-label", `Статус аккаунта ${account.username}`);
  for (const value of ["active", "suspended", "banned"] as const) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = statusLabel(value);
    option.selected = value === account.status;
    state.append(option);
  }
  state.addEventListener("change", () => void updateAccount(account, { status: state.value as Account["status"] }));
  const sessions = document.createElement("button");
  sessions.type = "button";
  sessions.className = "text-button";
  sessions.textContent = "Сессии";
  sessions.addEventListener("click", () => void openSessions(account));
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "text-button danger-text";
  remove.textContent = "Удалить";
  remove.addEventListener("click", () => void deleteAccount(account));
  actions.append(edit, state, sessions, remove);

  row.append(identity, created, statusCell, actions);
  return row;
}

async function updateAccount(account: Account, changes: { username?: string; status?: Account["status"] }): Promise<void> {
  try {
    await api(`/admin/api/accounts/${account.id}`, { method: "PATCH", body: JSON.stringify(changes) });
    showFlash(`Аккаунт ${account.username} обновлён.`);
    await loadAccounts();
  } catch (error) {
    showFlash(error instanceof Error ? error.message : "Не удалось обновить аккаунт.", true);
    await loadAccounts();
  }
}

async function editUsername(account: Account): Promise<void> {
  const username = window.prompt(`Новое имя для ${account.username}`, account.username);
  if (username === null || username.trim() === account.username) return;
  await updateAccount(account, { username });
}

async function deleteAccount(account: Account): Promise<void> {
  if (!window.confirm(`Удалить аккаунт «${account.username}» и все его сессии? Это действие нельзя отменить.`)) return;
  try {
    await api(`/admin/api/accounts/${account.id}`, { method: "DELETE" });
    if (selectedAccount?.id === account.id) closeSessions();
    showFlash(`Аккаунт ${account.username} удалён.`);
    await loadAccounts();
  } catch (error) {
    showFlash(error instanceof Error ? error.message : "Не удалось удалить аккаунт.", true);
  }
}

async function openSessions(account: Account): Promise<void> {
  try {
    selectedAccount = account;
    const result = await api<{ sessions: AccountSession[] }>(`/admin/api/accounts/${account.id}/sessions`);
    byId<HTMLElement>("sessions-title").textContent = `Сессии · ${account.username}`;
    sessionsContent.replaceChildren();
    if (result.sessions.length === 0) {
      const empty = document.createElement("p");
      empty.className = "hint";
      empty.textContent = "Сессий пока нет.";
      sessionsContent.append(empty);
    } else {
      const table = document.createElement("div");
      table.className = "sessions-list";
      for (const session of result.sessions) table.append(makeSessionRow(account, session));
      sessionsContent.append(table);
    }
    const revokeAll = document.createElement("button");
    revokeAll.type = "button";
    revokeAll.className = "button danger";
    revokeAll.textContent = "Отозвать все активные сессии";
    revokeAll.addEventListener("click", () => void revokeAllSessions(account));
    sessionsContent.append(revokeAll);
    sessionsPanel.hidden = false;
    sessionsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    showFlash(error instanceof Error ? error.message : "Не удалось загрузить сессии.", true);
  }
}

function makeSessionRow(account: Account, session: AccountSession): HTMLElement {
  const row = document.createElement("article");
  row.className = "session-row";
  const details = document.createElement("div");
  const sessionId = document.createElement("strong");
  sessionId.textContent = session.id;
  const meta = document.createElement("span");
  meta.textContent = `Создана ${formatDate(session.createdAt)} · Последняя активность ${formatDate(session.lastUsedAt)} · Истекает ${formatDate(session.expiresAt)}`;
  const userAgent = document.createElement("small");
  userAgent.textContent = session.userAgent ?? "Устройство не указано";
  details.append(sessionId, meta, userAgent);
  const action = document.createElement("button");
  action.type = "button";
  action.className = session.revokedAt ? "text-button" : "text-button danger-text";
  action.textContent = session.revokedAt ? `Отозвана ${formatDate(session.revokedAt)}` : "Отозвать";
  action.disabled = session.revokedAt !== null;
  action.addEventListener("click", () => void revokeSession(account, session));
  row.append(details, action);
  return row;
}

async function revokeSession(account: Account, session: AccountSession): Promise<void> {
  try {
    await api(`/admin/api/accounts/${account.id}/sessions/${session.id}/revoke`, { method: "POST", body: "{}" });
    showFlash("Сессия отозвана.");
    await openSessions(account);
  } catch (error) {
    showFlash(error instanceof Error ? error.message : "Не удалось отозвать сессию.", true);
  }
}

async function revokeAllSessions(account: Account): Promise<void> {
  if (!window.confirm(`Отозвать все активные сессии аккаунта ${account.username}?`)) return;
  try {
    const result = await api<{ revoked: number }>(`/admin/api/accounts/${account.id}/revoke-sessions`, { method: "POST", body: "{}" });
    showFlash(`Отозвано сессий: ${result.revoked}.`);
    await openSessions(account);
  } catch (error) {
    showFlash(error instanceof Error ? error.message : "Не удалось отозвать сессии.", true);
  }
}

function closeSessions(): void {
  sessionsPanel.hidden = true;
  selectedAccount = null;
}

function showApplication(): void {
  loginView.hidden = true;
  appView.hidden = false;
  void loadAccounts().catch((error: unknown) => {
    if (error instanceof Error && error.message.includes("Sign in")) {
      appView.hidden = true;
      loginView.hidden = false;
      return;
    }
    showFlash(error instanceof Error ? error.message : "Не удалось загрузить аккаунты.", true);
  });
}

byId<HTMLFormElement>("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.textContent = "";
  const passwordInput = byId<HTMLInputElement>("admin-password");
  try {
    await api("/admin/api/login", { method: "POST", body: JSON.stringify({ password: passwordInput.value }) });
    passwordInput.value = "";
    showApplication();
  } catch (error) {
    loginError.textContent = error instanceof Error ? error.message : "Не удалось войти.";
    passwordInput.value = "";
  }
});

byId<HTMLButtonElement>("logout-button").addEventListener("click", async () => {
  try {
    await api("/admin/api/logout", { method: "POST", body: "{}" });
  } finally {
    appView.hidden = true;
    loginView.hidden = false;
  }
});

byId<HTMLFormElement>("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const usernameInput = byId<HTMLInputElement>("new-username");
  const passwordInput = byId<HTMLInputElement>("new-password");
  const username = usernameInput.value;
  const password = passwordInput.value;
  try {
    await ready;
    const registration = client.startRegistration({ password });
    const start = await api<{ registrationResponse: string }>("/v1/register/start", {
      method: "POST",
      body: JSON.stringify({ username, registrationRequest: registration.registrationRequest }),
    });
    const finish = client.finishRegistration({
      clientRegistrationState: registration.clientRegistrationState,
      registrationResponse: start.registrationResponse,
      password,
    });
    await api("/v1/register/finish", {
      method: "POST",
      body: JSON.stringify({ username, registrationRecord: finish.registrationRecord }),
    });
    passwordInput.value = "";
    usernameInput.value = "";
    currentPage = 1;
    showFlash("Тестовый аккаунт создан.");
    await loadAccounts();
  } catch (error) {
    passwordInput.value = "";
    showFlash(error instanceof Error ? error.message : "Не удалось создать аккаунт.", true);
  }
});

byId<HTMLFormElement>("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  currentPage = 1;
  void loadAccounts().catch((error: unknown) => showFlash(error instanceof Error ? error.message : "Не удалось выполнить поиск.", true));
});

byId<HTMLInputElement>("search-input").addEventListener("input", () => {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => {
    currentPage = 1;
    void loadAccounts().catch((error: unknown) => showFlash(error instanceof Error ? error.message : "Не удалось выполнить поиск.", true));
  }, 250);
});

byId<HTMLSelectElement>("status-filter").addEventListener("change", () => {
  currentPage = 1;
  void loadAccounts().catch((error: unknown) => showFlash(error instanceof Error ? error.message : "Не удалось загрузить аккаунты.", true));
});

byId<HTMLButtonElement>("refresh-button").addEventListener("click", () => {
  void loadAccounts().catch((error: unknown) => showFlash(error instanceof Error ? error.message : "Не удалось обновить список.", true));
});

byId<HTMLButtonElement>("prev-page").addEventListener("click", () => {
  if (currentPage > 1) currentPage--;
  void loadAccounts().catch((error: unknown) => showFlash(error instanceof Error ? error.message : "Не удалось загрузить аккаунты.", true));
});

byId<HTMLButtonElement>("next-page").addEventListener("click", () => {
  if (!hasNextPage) return;
  currentPage++;
  void loadAccounts().catch((error: unknown) => showFlash(error instanceof Error ? error.message : "Не удалось загрузить аккаунты.", true));
});

byId<HTMLButtonElement>("close-sessions").addEventListener("click", closeSessions);
void ready.then(() => {
  void api("/admin/api/accounts?page=1").then(() => showApplication()).catch(() => undefined);
});
