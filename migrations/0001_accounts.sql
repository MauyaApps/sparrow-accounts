-- Аккаунты Sparrow. Таблицы радио (streams) не затрагиваются: у аккаунтов своя база.
CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  -- OPAQUE registration record (base64). Пароль и его производные сюда не попадают.
  opaque_record TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
  created_at    INTEGER NOT NULL, -- unix, секунды
  updated_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_hash      TEXT NOT NULL, -- hex SHA-256 текущего refresh-секрета
  prev_refresh_hash TEXT,          -- предыдущий: его повторное предъявление = кража, сессия отзывается
  created_at        INTEGER NOT NULL,
  last_used_at      INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  revoked_at        INTEGER,
  user_agent        TEXT
);
CREATE INDEX idx_sessions_user    ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
