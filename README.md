# Suhoput 2.0

Интернет-магазин розницы и приглашённых оптовых покупателей на WordPress/WooCommerce с дизайном владельца и обменом с МойСклад. Требования определены в [SPEC](docs/SPEC.md), текущая готовность — в [STATUS](docs/STATUS.md).

## Карта и чтение

Новый агент начинает с [AGENTS](AGENTS.md) и [STATUS](docs/STATUS.md), проверяет Git, затем выбирает задачу из [PLAN](docs/PLAN.md) и читает относящиеся к ней требования, [ARCHITECTURE](docs/ARCHITECTURE.md), [DECISIONS](docs/DECISIONS.md) и [ACCEPTANCE](docs/ACCEPTANCE.md). Для первого подробного планирования SPEC читается полностью.

| Документ | Содержимое |
| --- | --- |
| [AGENTS](AGENTS.md) | Постоянные правила работы и передачи |
| [SPEC](docs/SPEC.md) | Полное исходное ТЗ, паспорт и стабильный индекс REQ |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Утверждённое устройство и технические вопросы |
| [PLAN](docs/PLAN.md) | 11 этапов и 55 задач с критериями и зависимостями |
| [STATUS](docs/STATUS.md) | Текущая передача работы и препятствия |
| [ACCEPTANCE](docs/ACCEPTANCE.md) | Покрытие ТЗ, способы проверок и доказательства |
| [DECISIONS](docs/DECISIONS.md) | Основания решений и изменения требований |
| [ACCESS](docs/ACCESS.md) | Получение прав, тестовые контуры и заполнение локальной конфигурации |
| [COMPATIBILITY](docs/COMPATIBILITY.md) | Зафиксированные версии, лицензии и предварительный аудит ЮKassa |
| [CONTRACTS](docs/CONTRACTS.md) | Интерфейсы v1 и модель состояний/событий |
| [DESIGN](docs/DESIGN.md) | Карта исходной вёрстки и отсутствующих состояний |

## Окружение и запуск

Обследование 08.10.2026: исходная папка была пустой, родительские AGENTS.md не найдены. Среда — Windows, PowerShell Core 7.6.5, вывод UTF-8. Доступность определена через `Get-Command`; это не проверка установки WordPress или работоспособности всех служб.

| Инструмент/среда | Установленный факт |
| --- | --- |
| Git | `git --version` выполнена: 2.55.0.windows.5 |
| ripgrep | `rg --version` выполнена: 15.2.0 |
| Node.js | `node --version` выполнена: v24.19.0; используется для проверки документов |
| Docker и SSH | Docker Engine 29.8.0 и Compose 5.5.1 отвечают; SSH-соединения не проверялись |
| Python | Найден WindowsApps alias; работоспособность интерпретатора не подтверждена |
| PHP, Composer, WP-CLI, npm, gh, MariaDB/MySQL CLI | Не найдены в текущем PATH; отсутствие установки вне PATH не утверждается |
| WordPress/WooCommerce, PHP и база | Локально 7.1.3 / 11.2.0 / 8.3.35 / MariaDB 10.11.19, HPOS включён |
| Дизайн | Предоставлена папка владельца, сопоставление — DESIGN; текущая тема — минимальный каркас |

## Локальный стенд

Из корня проекта, PowerShell 7 / Docker с Linux-контейнерами:

```powershell
./infra/init-local.ps1
./tools/fetch-vendor.ps1
docker compose --env-file infra/.env.local -f infra/compose.yaml up -d --wait
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli sh /bootstrap.sh
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp suhoput queue tick
docker compose --env-file infra/.env.local -f infra/compose.yaml --profile queue up -d scheduler
```

Проверены первая установка и повтор bootstrap. Docker образы закреплены digest, WooCommerce ZIP проверяется SHA-256. WordPress доступен на http://localhost:18880, перехватчик почты — http://localhost:18881. Учётка стенда `local-admin`, пароль только в игнорируемом `infra/.env.local`, здесь не выводится. Сеть приложения/базы закрыта; localhost публикует отдельный прокси. HTTP API заблокирован локальным MU-обработчиком, почта направлена в Mailpit, задания от посещений и автообновления отключены. MU-обработчик относится только к инфраструктуре локального стенда и не включается в production. Интеграционные ключи из [ACCESS](docs/ACCESS.md) в этот закрытый стенд автоматически не передаются.

Два собственных плагина и классическая тема активны. Функции магазина проходят отдельные задачи PLAN; минимальная тема ещё не воспроизводит дизайн. ЮKassa на стенде не установлена.

```powershell
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp eval-file /tests/local-safety.php
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli php /tests/contracts.php
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp eval-file /tests/schema.php
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp eval-file /tests/schema-upgrade.php
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp eval-file /tests/journal.php
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp eval-file /tests/workers.php
node tests/worker-crashes.cjs
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli wp eval-file /tests/scheduler.php
node tests/queue-concurrency.cjs
node tests/queue-minute.cjs
docker compose --env-file infra/.env.local -f infra/compose.yaml run --rm cli sh /tests/lint.sh
node tests/concurrency.cjs
./tools/check-secrets.ps1
```

Браузерные зависимости: pnpm 11.25.0, lockfile фиксирует Playwright 1.62.1. На текущем компьютере pnpm доступен по пути bundled runtime:

```powershell
& 'C:/Users/komba/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/pnpm.cmd' install --frozen-lockfile
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path (Get-Location) '.cache/ms-playwright'
& 'C:/Users/komba/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/fallback/pnpm.cmd' exec playwright install chromium --only-shell
node tests/browser-smoke.cjs
```

Для другой среды использовать установленный pnpm той же версии; абсолютный bundled путь относится к этому компьютеру. В CI Linux используется собственная установка браузера. Smoke проверяет запуск каркаса desktop/mobile, а не покупательскую приёмку TASK-040. PHP-имитации не доказывают внешний резерв/платёж. Команды Docker, HTTP localhost и браузер требуют разрешения песочницы в этой сессии.

Остановка только этого проекта без удаления данных:

```powershell
docker compose --env-file infra/.env.local -f infra/compose.yaml --profile queue down
```

Минутный сервис `scheduler` работает через системный `sleep`/WP-CLI без посещений сайта. Первый `queue tick` на чистом стенде завершает штатную миграцию Action Scheduler 4.1.0; новый процесс выбирает DBStore. При `SUHOPUT_SYSTEM_QUEUE_ENABLED=true` отключён асинхронный запуск AS из HTTP. Сервис ограничивает процесс 55 секундами, очередь блокирует наложения и начинает следующий запуск по границе минуты. При проверках очереди остановить `scheduler`, чтобы тестовые адаптеры не обрабатывались другим процессом; затем запустить снова.

`docker compose --env-file infra/.env.local -f infra/compose.yaml logs --timestamps --tail 20 scheduler` показывает системные запуски. В базе сохраняются время начала/окончания и счётчик (`suhoput_queue_*`), для операций — ошибки и следующие попытки, для периодических заданий — последнее успешное выполнение. Менеджерский интерфейс/реальная доставка тревог добавляются TASK-038/039/046. Перезапуск сервиса сохраняет очередь в базе.

Для будущего Linux-окружения подготовлены `infra/systemd/suhoput-queue.service` и `.timer` (раз в минуту, предел 55 секунд). Это шаблоны: перед установкой обследовать сервер и задать фактические пути/пользователя/WP-CLI, `DISABLE_WP_CRON=true` и `SUHOPUT_SYSTEM_QUEUE_ENABLED=true`. Сервис обслуживает также штатные группы WooCommerce; системный вызов остальных необходимых cron-событий WordPress определяется TASK-046. На production шаблоны не устанавливались. Восстановленная копия остаётся с запрещёнными внешними действиями до сверки TASK-048.

VPS Timeweb, S3 Selectel, домен и почтовый домен reg.ru указаны владельцем в ТЗ; доступы, адреса и состояние не обследованы. Порядок размещения и эксплуатации задаёт [SPEC](docs/SPEC.md#почта-и-эксплуатация). Секреты задаются в соответствующем окружении, а не в документах.

## Git и проверки документов

Git инициализирован с веткой `main`. Состояние автора, коммита, индекса и подключения GitHub фиксируется только в STATUS. Владелец предоставил допустимые данные автора и URL.

В `.gitattributes` для Markdown закреплён LF: исходное ТЗ содержит LF, а системная настройка Git `core.autocrlf=true` иначе меняла бы его байты при следующем checkout и нарушала проверку SHA-256. Это служебная настройка для восьми документов, [DEC-014](docs/DECISIONS.md#dec-014).

Выполненные проверки и проверенная версия фиксируются в [ACCEPTANCE](docs/ACCEPTANCE.md#доказательства-подготовки-документов). Следующие команды повторяются из корня проекта:

```powershell
git status --short --branch
git diff --check
git diff --cached --check
git check-attr text eol -- docs/SPEC.md
```

Проверка из корня проекта: `node tools/validate-docs.cjs`. Она подтверждает сохранность исходных 164256 байт SPEC по SHA-256, покрытие 319 исходных групп и уточнений REQ-320–321, 62 исходных критерия, связи с 55 задачами, отсутствие циклов и относительные ссылки. Также проверяется финальный порядок ЮKassa. Внешние API и функции магазина команда не испытывает.

Хеш подтверждает сохранность исходного импорта, а не допустимость бизнес-изменения. При согласованном изменении ТЗ сохранять историю Git и исходный паспорт, оформлять действующую редакцию и её проверку через DECISIONS; не менять ожидаемый хеш только ради успешного результата.
