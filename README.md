# Suhoput 2.0

TASK-047 остаётся **blocked**. Protected native retention apply, durable intent/origins/tombstones и retained suffix проверены в отдельном synthetic Linux repository. Metadata/clock/freshness исправления установлены на STAGE-B в runtime `fa89e3a`; [EXEC-CHK-063](docs/ACCEPTANCE.md#exec-chk-063). Actual read-only S3 audit:13 snapshots/7 logs/candidates0, native read-data/checksum PASS. SITE-A/57 прежних config SHA/старые службы/таймеры/порты сохранены; live apply/deletion not_run,4 новых timers disabled.

Native scale probe выявил ограничение месячного режима: полный inventory43 950 synthetic metadata snapshots не завершился за90с, а arrivals блокируют exact cohort digest. Убран повторный `cat snapshot` (49 snapshots:50,57→23,42с), исправлены observation clock и15min freshness сразу перед effect;207 backup tests и protected native сценарий PASS. [Catalog/frozen cohort proposal](docs/ARCHITECTURE.md#task-047-native-scale-proposal) ещё не реализован. Distinct month corpus/Inspector/S3 budget/cadence/lag/errors/space/реальные30д/anchor остаются gates. Прежняя оценка284,1144 ₽/2,56381 GiB относится к малому inventory. Public rates, owner-run PASS и раздельное хранение kit/пароля подтверждены; точная передача — [STATUS](docs/STATUS.md).

Worker/ROW/8units установлены только на STAGE-B. Полное восстановление сохранённого owner-kit на текущем ПК выполнено владельцем12.10.2026 16:27–16:29UTC: ранний9331-file full, DB,7logs→000007/450, controls0→1 и all-media PASS, чтения VPS0/S3writes0. Владелец подтвердил запуск и приёмку; kit runtime722f356 остаётся неизменным. Текущий ПК допустим как среда, отдельная от VPS; другой ПК покупать не требуется. Лимиты500RUB/месяц/10GiB сохраняются. [Пакет](docs/INFRASTRUCTURE.md#task-047-change-proposal) разрешён DEC-025; [инструкция владельца и тарифов](docs/BACKUP.md), [runner](infra/backup/retention_native.py), [счётчики](infra/backup/meter.py). SITE-A/старые таймеры сохраняются, TASK-048 не принята.

Интернет-магазин розницы и приглашённых оптовых покупателей на WordPress/WooCommerce с дизайном владельца и обменом с МойСклад. Требования определены в [SPEC](docs/SPEC.md), текущая готовность — в [STATUS](docs/STATUS.md).

## Карта и чтение

Для TASK-044 подготовлены [входы инфраструктуры](docs/ACCESS.md#infrastructure-inputs) и [протокол обследования](docs/INFRASTRUCTURE.md#read-only-survey). Шаблон `infra/.env.infrastructure.example` копируется в игнорируемый `infra/.env.infrastructure.local` только при отсутствии существующей копии; значения вводятся локально, файл не исполняется. Протокол сначала читает подтверждённые ресурсы. Создание стенда требует конкретного согласования после обследования; локальный Compose сам по себе не является конфигурацией VPS. Фактическая проверка и её незапущенные части — [ACCEPTANCE](docs/ACCEPTANCE.md#exec-chk-034).

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

VPS Timeweb, отдельные STAGE-B/S3-B, домен и почта обследованы в TASK-044; результаты и ограничения — [INFRASTRUCTURE](docs/INFRASTRUCTURE.md) и ACCEPTANCE. SITE-A сохраняется закрытым. Реальные S3 upload/read/integrity и synthetic DB/PITR control проверены; целевые проектные S3 copies/PITR/media control проверены EXEC-CHK-058; постоянное расписание, retention и полное восстановление владельцем ещё не приняты. Порядок размещения и эксплуатации задаёт [SPEC](docs/SPEC.md#почта-и-эксплуатация). Секреты задаются в соответствующем окружении, а не в документах.

## Git и проверки документов

TASK-019: `pnpm test:commerce` (или `node tests/commerce-suite.cjs`) запускает серверные правила контекста, реальные локальные HTTP/Store API, смену прав/сессий, конкурентные квоты и письмо имитированного гостевого заказа в Mailpit. Внешнего резерва/платежа нет. Используются example.invalid, временные настройки и только собственные fixture; suite восстанавливает настройки и удаляет свои объекты/письма. На Windows задать PLAYWRIGHT_BROWSERS_PATH как выше. Suite входит в foundation CI.

WooCommerce → Гостевые ограничения: менеджер/администратор задаёт окно и лимиты браузера/общего IP; defaults 10/120 действий за 60 секунд и 2/20 активных неоплаченных намерений. Настройки хранятся в `suhoput_guest_limits`, не публикуются REST. Не доверять Forwarded/X-Forwarded-For от клиента: перед production настроить реальный REMOTE_ADDR только от проверенного прокси (TASK-046); на закрытом local все браузеры действительно имеют общий адрес прокси. Не освобождать unknown слот удалением cookie/по времени. Будущий адаптер вызывает settle после подтверждения; это не складская гарантия и не разрешение EXT-013.

Foundation отключает page-cache. Классическое оформление сохраняется; альтернативный Store checkout и перенос Cart-Token закрыты. При смене сессии/прав корзина пересчитывается и требует кнопки подтверждения; отключённый опт сохраняет собственную историю. Полный импорт/публичная выдача/проверка актуальных цен/доставки и внешний резерв ещё не реализованы. Протокол и точки подключения — [CONTRACTS](docs/CONTRACTS.md#контекст-и-гостевые-ограничения-task-019).

TASK-018: `pnpm test:order-access` (или `node tests/order-access-suite.cjs`) проверяет серверное владение, одновременное одноразовое подтверждение, браузерные страницы/API и письма Mailpit. На Windows использовать тот же PLAYWRIGHT_BROWSERS_PATH, что выше. Проверки работают только на закрытом local Compose, генерируют example.invalid и удаляют только собственные fixture и письма. Исходные письма/ключи/пароли не выводятся. Эта проверка включена в обязательный CI.

Кабинет включает форму доступа к гостевому заказу. Письмо открывается в том же браузере и подтверждается кнопкой; для привязки нужно войти и запросить новое письмо из целевого аккаунта. Совпадение email/контрагента не связывает историю. Признак заказа сайта задаётся сервером checkout, исторические/ручные документы в кабинет не импортируются. Полный checkout/синхронизация внешних статусов/production-кеш подтверждаются последующими задачами; текущая тема ещё не воспроизводит дизайн. Технический протокол — [CONTRACTS](docs/CONTRACTS.md#доступ-к-заказам-task-018).

TASK-016 проверяется только на локальном Compose с Mailpit: `pnpm test:accounts` (или `node tests/accounts-suite.cjs`) запускает реальные WP/WC операции, семь сценариев отказов БД, конкуренцию/гибель процесса и браузерные формы. На Windows задать `PLAYWRIGHT_BROWSERS_PATH` как `.cache/ms-playwright`, если браузеры установлены туда. Пароли генерируются в памяти, используются только адреса `example.invalid`; исходные письма/ключи/пароли не выводятся. Fixture удаляет свои аккаунты, товары/гостевой CRUD-заказ и собственные браузерные письма Mailpit; посторонняя почта не очищается. Все этапы входят в обязательный CI. Полный гостевой checkout, доменная доставка писем, права на историю и оптовое приглашение проверяются последующими задачами.

Core включает регистрацию на странице My Account, ввод собственного пароля, нормализованный вход по email и необязательный аккаунт для гостевого оформления. Собственная уникальность охватывает штатные `wp_insert_user`/`wp_update_user` и постоянный `WC_Customer::save`; сырой SQL сторонних модулей не является поддерживаемым путём. Нужны InnoDB для users/usermeta/accounts и mysqli; вложенная транзакция вызывающего кода отклоняется. Оптовый тип/историческая привязка не меняются при смене email. Перед рабочим размещением проверить существующих пользователей/дубли и целевое кеширование в соответствующей задаче размещения; рабочие данные этим тестом не мигрировались.

Ранние проверки МойСклад TASK-006–009 выполняются отдельно от закрытого WordPress:

```powershell
./tests/moysklad-probe.ps1
./tests/moysklad-control.ps1
./tests/moysklad-document-control.ps1
./tests/moysklad-examples.ps1
./tools/probe-moysklad.ps1 -StopAfterCatalogPages 2
./tools/probe-moysklad.ps1 -Resume -MaxDocuments 50
```

Первая команда использует только синтетические ответы и входит в CI без секретов. GET-инструмент читает исключённый `infra/.env.integrations.local`, сверяет активные «Склад Грозный»/«Основной склад», сохраняет обезличенные контрольные точки/агрегаты и служебные ID в `.cache/moysklad`. Исходные ответы с данными клиентов/сырыми кодами не сохраняются. Без `-Resume` создаётся новая контрольная точка каталога; `-Resume` продолжает только совпадающий контур. Ошибка/изменение размера/дубли не дают успешной полноты; стабильный size не гарантирует атомарный снимок. MaxDocuments ограничивает выборку **каждого** вида документа (1…500); все позиции выбранных документов читаются полностью, полнота выборки указана отдельно. StopAfterCatalogPages — штатная остановка после атомарной записи точки, не тест аварийного завершения процесса. Реальное происхождение цен, внешняя атомарность резерва и полные исходные коды этим инструментом не подтверждаются. Пакет изменяющих испытаний и очистка — [ACCESS](docs/ACCESS.md#контрольные-изменения-мойсклад--пакет-ms-probe-20261008-a); разрешение на запись этим запуском не выдаётся.

Git инициализирован с веткой `main`. Состояние автора, коммита, индекса и подключения GitHub фиксируется только в STATUS. Владелец предоставил допустимые данные автора и URL.

Поиск существующих примеров без изменений: `./tools/find-moysklad-examples.ps1 -StopAfterDocumentPages 1`, затем `./tools/find-moysklad-examples.ps1 -Resume`. Без StopAfterDocumentPages читается полный доступный контур demand выбранной организации/склада. Свежий каталог показывает известное/неизвестное количество фото; положительный случай дополнительно читает images. Документы читаются expand=positions с limit=100, неполный expand заменяется полным отдельным чтением позиций. Неизвестная маркировочная структура и нераскрытый тег 1162 сохраняются как кандидаты без raw-кодов/PII. checkpoint фиксируется после полной страницы; изменившийся size/дубли/неполные позиции не дают завершения. `-Resume` использует сохранённый каталог с проверкой size, а не новый снимок всех карточек. Реальное отсутствие данных в доступных ответах не доказывает отсутствие в других контурах/UI; полный исходный код требует независимого контрольного образца. Полнота сканирования/разрешительная проверка не заявляются. Инструкция владельцу — ACCESS.

Согласованный изменяющий контроль MS-PROBE-20261008-A выполнен и очищен, [EXEC-CHK-021–023](docs/ACCEPTANCE.md#exec-chk-021). `tools/control-moysklad-prices.ps1` имеет фазы Prices, RemoveOwnPrice, Cleanup; `tools/control-moysklad-documents.ps1` — RepairChannel, Inspect, Preflight, Prepare, RecoverAgent, Exercise, Cleanup. **Не запускать изменяющие фазы как обычный smoke**: они создают/проводят/удаляют реальные тестовые складские объекты и требуют конкретного согласования ACCESS. Нужны проверенная локальная конфигурация, сохранённый манифест намерений и локальный файл выбора контрагента/подтверждения автоматизаций. Манифест не удалять/не сбрасывать для повтора пакета: unknown требует GET-сверки, confirmed переиспользуется после проверки, prepared продолжает исходное намерение, удалённый пакет заново не создаётся. Контрагент и розничный заказ восстанавливались в отдельных процессах. Inspect/Preflight выполняют GET, но могут остановиться после очистки из-за удалённых объектов; Inspect подтверждает отсутствие unknown и число каналов. Cleanup сверяет чужие связи, отменяет только проведённые документы пакета и подтверждает stock/reserve/inTransit=0 до удаления справочников. Файловый commit подтверждается до HTTP; повторяются только файловые IOException, неизвестный POST/PUT автоматически не повторяется. Четыре независимых набора тестов входят в CI без credentials; цена/резерв/коды в рабочем API ими не доказываются. TASK-015 заблокирован доказанным ограничением общего резерва и оставшимися внешними доказательствами.

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

Отдельная конфигурация стенда — `infra/staging/compose.yaml`; она использует собственные БД/тома, Mailpit и staging guard. Поля защищённой среды перечислены в `infra/.env.staging.example`. Только новые синтетические данные; рабочие API/SMTP credentials туда не добавляются. Локальная проверка: `node tests/staging-suite.cjs <ignored-env-file> <unique-project-name>`. Имена контейнеров, сетей и томов должны быть свободны; оболочка отказывает при коллизии, после проверки останавливает только свой проект и сохраняет его тома.

На обследованном VPS перед первым WordPress bootstrap сначала создаются **только** новые `db` и `mailpit`, затем root выполняет `sh infra/staging/host-boundary.sh <stage-project>`. Это добавляет IPv4/IPv6 INPUT DROP только для нового internal bridge и проверяет позицию правила перед разрешениями. До запуска PHP обязательны фактические проверки закрытого host gateway, внешнего TCP/SMTP и сохранности старых служб/файлов/firewall. Простое `internal: true` не закрывает службы самого хоста. Полный порядок и ограничения — [INFRASTRUCTURE](docs/INFRASTRUCTURE.md#stage-proposal-20261011).

Стенд публикует только `127.0.0.1:18890` (WordPress) и `127.0.0.1:18891` (Mailpit); владелец подключается через SSH-туннель с действующим host trust. Пробросы SSH: `-L 127.0.0.1:18890:127.0.0.1:18890 -L 127.0.0.1:18891:127.0.0.1:18891`, `-N`, `StrictHostKeyChecking=yes`; использовать проверенные host/user/key/known_hosts целевого окружения. На Windows подготовлен ignored local helper и защищённый credential, точные пути — [STATUS](docs/STATUS.md#следующий-шаг). Пока туннель открыт, адреса — `http://localhost:18890/` и `http://localhost:18891/`; это частный HTTP внутри SSH. Контейнеры не имеют автоматического restart policy. Перед любым повторным запуском надо проверить host boundary и сетевую изоляцию; после reboot/UFW reload прежний результат не считается действующим доказательством. Откат до приёмки — остановить только stage-проект, сохранив данные. Выходные проверки выполняются на целевом VPS отдельно от локального suite; Release, рабочая почта и копии не входят в эту конфигурацию.
