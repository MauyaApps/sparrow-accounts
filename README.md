# Sparrow Account Platform

Локальная тестовая система аккаунтов Sparrow: OPAQUE-регистрация и вход, подписанные access-токены, refresh-сессии и локальная административная панель. Backend работает на Cloudflare Workers + D1 + Durable Objects; frontend панели запускается отдельным Vite-сервером только на `127.0.0.1`.

## Локальный запуск

Требуется Node.js 22 или новее.

```powershell
npm install
npm test
npm run check
npm run migrate:local
npm run dev
```

`npm run dev` запускает API на `http://127.0.0.1:8787` и панель на `http://127.0.0.1:5173`. Перед запуском команда создаёт `.dev.vars` с локальными OPAQUE- и signing-секретами, если файла ещё нет. Файл игнорируется Git. Пароль админки можно посмотреть в `.dev.vars`; он генерируется случайно и должен оставаться локальным.

Если `.dev.vars` уже существует, скрипт его не перезаписывает. Убедитесь, что в нём есть `LOCAL_ADMIN_ENABLED=true`, `LOCAL_ADMIN_PASSWORD` (минимум 16 символов), `LOCAL_ADMIN_SESSION_SECRET` (минимум 32 символа) и `LOCAL_ADMIN_ORIGIN=http://127.0.0.1:5173`.

## Возможности локальной панели

- Создание аккаунта через настоящий двухшаговый OPAQUE flow; открытый пароль остаётся в браузере.
- Список, поиск и фильтрация аккаунтов.
- Изменение имени и статуса (`active`, `suspended`, `banned`).
- Просмотр и отзыв отдельной сессии или всех сессий пользователя.
- Удаление аккаунта вместе с его сессиями.

Админские API работают только при локальном `LOCAL_ADMIN_ENABLED=true`, запросе к loopback-хосту и правильном `Origin`. Панель не включена в Worker bundle и не публикуется `wrangler deploy`. Админская cookie подписана HMAC, помечена `HttpOnly` и `SameSite=Strict`. Не используй эту локальную панель для реальных аккаунтов.

Собрать frontend для проверки:

```powershell
npm run admin:build
```

## Cloudflare

Account API использует отдельную Cloudflare D1 `sparrow-account-db`; её UUID указан в `wrangler.jsonc`. База изолирована от радио и других проектов. Миграция `0001_accounts.sql` применена к этой базе. Для последующего деплоя Worker задай `OPAQUE_SERVER_SETUP` и `TOKEN_SIGNING_KEY` в Cloudflare Secrets, затем запускай:

```powershell
npm run deploy
```

Cloudflare Worker публикует только account API; локальная админ-панель при этом не публикуется. Не пересоздавай `OPAQUE_SERVER_SETUP` после появления аккаунтов: существующие OPAQUE-записи перестанут проверяться.

## API

| Метод и путь | Назначение |
|---|---|
| `POST /v1/register/start`, `/v1/register/finish` | OPAQUE-регистрация |
| `POST /v1/login/start`, `/v1/login/finish` | OPAQUE-вход и выдача токенов |
| `POST /v1/token/refresh` | Ротация refresh-токена |
| `GET /v1/me`, `POST /v1/logout` | Данные пользователя и завершение сессии |
| `POST /v1/password/verify/{start,finish}`, `/v1/password/{start,finish}` | Подтверждение текущего и смена пароля |
| `GET /v1/keys` | Публичный ключ для проверки access-токенов |

Ошибки возвращаются в JSON `{ "error": { "code": "...", "message": "..." } }`.

## Криптография и сессии

- OPAQUE (`@serenity-kit/opaque` WASM) не передаёт серверу пароль и его хеш.
- Access-токены подписываются Ed25519 (`EdDSA`) и действуют 10 минут.
- Refresh-секрет хранится в D1 только как SHA-256-хеш; ротация выполняется атомарно, срок жизни — до 180 дней.
- Промежуточное состояние входа, одноразовые reauth-токены и лимиты живут в Durable Objects.
- Учётные данные не включаются в ошибки и логи.

## Проверки

`npm test` проверяет OPAQUE-WASM, SQL-схему и HTTP/API сценарии. `npm run check` проверяет TypeScript backend и административный frontend. `npm run admin:build` проверяет сборку UI и WASM-клиента.
