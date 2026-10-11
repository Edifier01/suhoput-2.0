# Копии и восстановление владельцем — TASK-047

**Подготовленный протокол, не действующая система копий.** Готовность — [STATUS](STATUS.md), согласованные объекты/операции — [INFRASTRUCTURE](INFRASTRUCTURE.md#task-047-change-proposal), требования — [TASK-047](PLAN.md#task-047) и [SPEC](SPEC.md#почта-и-эксплуатация). Самостоятельное назначение документа — порядок восстановления и критерии проверки владельцем. Целевые uploads/retention/DB restore/PITR ещё не запускались: новый PutObject403. Отдельный локальный архивный control описан ниже. Команды будущего восстановления нельзя применять к SITE-A.

## Независимый комплект владельца

Нужны защищённые endpoint/region/bucket/prefix S3-B, отдельный S3-B credential, **новый** recovery password репозитория, проверенный официальный restic binary/его SHA-256, SHA приложения и манифест компонентов. S3 credential не заменяет пароль расшифровки. Копия пароля только на VPS или внутри самого репозитория недостаточна. Прежний backup-key/password не используются.

DPAPI credential привязан к текущему Windows-профилю. Переносимый защищённый экспорт и восстановление на другом компьютере ещё не подготовлены/не испытаны. Секреты не передавать в чат, Git, PR, receipt или argv. Серверные credential/password files — root0600 в root0700 каталоге. Проверять происхождение/права, читать env как данные, не исполнять его как shell-код.

Кандидат — [restic0.19.1](https://restic.net/blog/2026-07-05/restic-0.19.1-released/), repository format2, проверка TLS/hostname и path-style S3. Документация [repository/S3](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html) изучена11.10.2026. Официальный binary скачан локально, SHA-256 совпал с Release SHA256SUMS; локальное архивирование/чтение/restore испытаны. Подпись Release ещё не проверена; на VPS binary не установлен, совместимость S3-B не испытана. До целевого применения проверить подпись, фиксировать версию в ACCEPTANCE.

## Состав копий и контроля

- Hourly: транзакционный dump только stage schema, точные base file/position, полное логическое состояние uploads с передачей изменённых блоков, UTC/source-generation/instance identity, SHA/bytes. Live MariaDB datadir не заменяет dump. Сейчас61 таблица InnoDB; смена engine/DDL требует новой проверки согласованности.
- Daily full и `pre-update`: дополнительно полный WordPress/WooCommerce, собственные plugins/theme/mu-plugin и bind-mounted файлы, конфигурация и версионный манифест. Full восстанавливается без файлов рабочей площадки. Успешный pre-update receipt обязателен до существенного обновления.
- Binlog: immutable закрытые файлы, выгрузка не реже минуты, SHA/bytes, проверка checksum штатным `mariadb-binlog`, непрерывная цепочка одной generation и heartbeat **после** подтверждённого upload. Lag>60с, gap/смена generation/rollback clock дают ошибку. Exit0 timer не доказывает сохранённые данные.

`mariadb-dump --single-transaction --master-data=2` — кандидат для InnoDB согласно [MariaDB dump](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump). При изменении media во время захвата проверить согласованность, не принимать snapshot автоматически. Полная owner-проверка включает реально прочитанные и расшифрованные данные, а не только наличие объектов.

## Восстановление в контрольный контур

1. Зафиксировать UTC сбоя и точный target file/position с проверенной границей события/транзакции. Выбрать base до target, full с нужным кодом и media snapshot по расписанию. Недоступный target не заменять молча последней точкой. Сверить S3-B/prefix, версии и доступ owner-ключом.
2. Использовать новый пустой каталог и отдельный DB instance/volume, проверить Docker labels/image/mounts/отсутствие коллизии непосредственно перед импортом. Исходный stage и SITE-A не являются целью. До bootstrap выключить egress/внешние адаптеры/cron/AS/системную очередь, оставить `event_scheduler=OFF`; контрольная DB без публичного порта/сети приложения. Проверить host boundary; будущие synthetic письма идут в Mailpit.
3. Реально выполнить `restic check --read-data`, затем `restic restore <verified-snapshot-id> --target <new-control-directory> --verify`. Это сетевые операции с расходами и lock-файлами, пока **not_run**. Проверить SHA/bytes SQL/media/кода и общую source-generation журналов. Не применять repair/unlock/forget для сокрытия ошибок. Основание — [restic restore](https://restic.readthedocs.io/en/stable/050_restore.html).
4. Импортировать dump в отдельный контрольный MariaDB10.11.19 instance. Для ROW replay сохранить исходное имя схемы **в новом instance**; переименование SQL или `--database` не являются изоляцией row events. Пароль не передавать в argv, SQL/data не выводить в отчёт.
5. Проверить каждый binlog штатным инструментом и применить непрерывную цепочку от base file/position до target. `--start-position` относится к первому файлу, `--stop-position` к последнему; сохранять один контролируемый SQL-сеанс. Для wall-clock stop отдельно подтвердить UTC/TZ и отсутствие partial transaction. Основание — [PITR](https://mariadb.com/docs/server/server-usage/backup-and-restore/mariadb-backup/point-in-time-recovery-pitr-mariadb-backup) и [binlog options](https://mariadb.com/docs/server/clients-and-utilities/logging-tools/mariadb-binlog/mariadb-binlog-options). Replay ещё не испытан.
6. Из восстановленной DB проверить synthetic заказ и служебную операцию **после base**, значения/уникальность/исторические ID; событие после stop должно отсутствовать. Собрать originals/`_wp_attached_file`, `_wp_attachment_metadata` (sizes/original_image), product/gallery references. Неизвестная сериализация или неполный список означает незавершённую проверку. Каждый referenced файл должен существовать внутри restored uploads и совпадать по SHA/bytes. Новый файл после последней media snapshot не считается сохранённым минутным binlog; медиа имеет hourly расписание.
7. Зафиксировать начало/конец, последний восстановленный commit/event, длительность, версии, code SHA и snapshot IDs в закрытом receipt; в ACCEPTANCE — обезличенный результат. Оставить контрольный контур закрытым. Сверка внешних связей/денег/резервов, старая очередь и общие RPO≤5мин/RTO≤4ч сервиса — [TASK-048](PLAN.md#task-048)/TASK-054, этим протоколом не закрыты.

## Retention, ресурсы и ошибки

Сохранять точки30д и prerequisite base перед началом окна с её цепочкой; prerequisite может временно лежать сверх30д. Перед forget/prune проверить старейшую остающуюся точку реальным восстановлением. Unknown snapshots/другой источник/gap/ошибка integrity/restore/отсутствие owner-key останавливают удаление. Автоматический retention ещё не реализован. [Restic retention](https://restic.readthedocs.io/en/stable/060_forget.html) требует проверенных tags/grouping, а не слепого применения примера.

Контролировать disk/inodes/spool/cache, S3 bytes, paid requests/egress, job duration, latest successful base/full/binlog heartbeat и ошибки. Нужны согласованные RUB/GiB ceilings, тарифы, фактические счётчики и сверка биллинга. При превышении сохранить годные копии, сообщить ошибку и условие снятия в STATUS; не сокращать30д/частоту и не удалять prerequisite ради зелёного статуса. Настоящая почта alerts — TASK-046, стенд — Mailpit; мониторинг пока не установлен.

## Локальные проверки

`python3 tests/backup_model_test.py` выполняет только synthetic сценарии. Подготовленный `tools/backup_model.py` читает локальный JSON/каталог и не меняет DB/S3:

```text
python3 tools/backup_model.py chain <local-chain-evidence.json>
python3 tools/backup_model.py files <local-inventory.json> --root <isolated-restored-directory>
python3 tools/backup_model.py retention <local-snapshot-evidence.json>
python3 tools/backup_model.py cost <local-month-projection.json>
```

Формат входов — fixtures в [тестах](../tests/backup_model_test.py). Chain проверяет порядок/байтовый охват/heartbeat; provenance, event checksums/boundaries и atomic replay требуют настоящих испытаний. Files проверяет SHA/bytes и **предоставленные** references, сам не извлекает их из DB. Retention возвращает `apply_allowed=false`/`history_coverage_verified=false`, отдельно указывает наличие anchor перед cutoff; cost — `provider_billing_verified=false`. Эти проверки не доказывают encrypted archives, полноту DB/media, запись S3, расписание/мониторинг,30д истории или восстановление.

Отдельный [архивный control](../tests/backup-archive-local.sh) действительно выполняет restic init/backup/check --read-data/restore --verify на новых синтетических текстовых файлах и media, проверяет byte equality, отказ неверного пароля и выявление намеренно повреждённого pack. Это **локальная файловая repository**, не SQL import, не binlog и не S3. Одноразовый пароль генерируется внутри tmpfs, секреты не монтируются. Запуск только в новом контейнере без сети с пустым `/control`; сначала получить официальный restic binary и проверить SHA. Пример PowerShell из корня проекта, без скачивания/установки на VPS:

```powershell
$taskRoot = (Get-Location).Path
$taskBinary = Join-Path $taskRoot '.cache/infrastructure/restic-0.19.1/restic'
$taskScript = Join-Path $taskRoot 'tests/backup-archive-local.sh'
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 384m --cpus 1 --tmpfs /control:rw,exec,nosuid,nodev,size=134217728,mode=0700 --tmpfs /tmp:rw,nosuid,nodev,size=16777216 --mount "type=bind,source=$taskBinary,target=/input/restic,readonly" --mount "type=bind,source=$taskScript,target=/input/test.sh,readonly" --entrypoint sh wordpress:7.1.3-php8.3-apache@sha256:8ecd8d8e374167ea22235acf30f80d1165b82f07ffa5bcef90c1cad8f7be251f /input/test.sh
if ($LASTEXITCODE -ne 0) { throw 'Local archive control failed' }
```

Скрипт проверяет digest restic, не удаляет host-файлы и повреждает только собственный ephemeral pack после успешного восстановления. Первый trial11.10.2026 остановился на fault injection: pack mode read-only вместе с cap-drop ALL запретил truncate. Исправлен fixture — проверка своего uid/chmod своего tmpfs-файла; ограничения контейнера сохранены. Повтор17:51 UTC exit0, [EXEC-CHK-053](ACCEPTANCE.md#exec-chk-053). Этот сценарий не доказывает восстановление владельцем на независимом компьютере или выполнение TASK-047/048.
