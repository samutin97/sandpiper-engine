# hiddify-core, ветка `hardened`: изменения форка

Основа: hiddify-core v5.9.8 (`6777b7f`), hiddify-sing-box `9dbf55dde`, ray2sing `6974ad6`.
Все подмодули с правками — на ветках `hardened`: `hiddify-sing-box`, `ray2sing`,
`hiddify-sing-box/replace/amneziawg-go` (влит апстрим v3.1.20261116), `hiddify-sing-box/replace/sing`.
Номера HC-xx и P-xx — находки внутреннего аудита (он не публикуется). Хеши коммитов ниже — из истории
разработки до публикации; если при публикации история пересобиралась (обезличенный автор), в этом
репозитории этих хешей может не быть. Подмодули с правками публикуются как отдельные репозитории
(см. `.gitmodules` здесь и в `hiddify-sing-box`).

Тесты форка лежат рядом с кодом (`hardened_*_test.go`, `h_*_test.go`) и добавлены в git принудительно
(`.gitignore` апстрима исключает `*_test.go`).

## Локальные порты и управление (утечка A, заметность)
- Clash API без TCP-порта; на desktop только по `clash-api-listen` (случайный порт, секрет 32 байта, CORS только свой origin). Секрет сравнивается за постоянное время. (HC-04, HC-35)
- Локальный mixed-прокси: на мобильных в VPN-режиме не создаётся никогда; всегда с паролем (свой или случайный на процесс, нейтральное имя); SOCKS5 UDP ASSOCIATE выключен (`disable_udp` в форке); только 127.0.0.1 на мобильных; `mixed-port: 0` — свободный порт; RPC `GetLocalProxyInfo`; realm 407 — `proxy`. LAN-раздача только с паролем ≥ 8. (HC-17)
- gRPC: режимы без аутентификации запрещены на Android/iOS, на desktop — только с секретом ≥ 32; unix-сокеты (`unix:`, `unix-abstract:`/`@`, проверка `SO_PEERCRED`), свободный TCP-порт, `GetListenAddress`; нейтральный сертификат ECDSA (без «Hiddify, Inc.»). (HC-05, HC-08)
- pprof — только сборка с тегом `with_pprof` (и в libbox); debug не от уровня логов. (HC-07)

## Секреты и данные
- `SetupRequest.data_path`: данные ядра во внутреннем каталоге (на Android по умолчанию `base_path`), umask 077, миграция и удаление старого `<working_dir>/data`; `current-config.json` не пишется (кроме тега `with_debug_files`). (HC-06)
- Логи для приложения очищаются от ссылок, UUID, ключей, паролей, адресов (адреса — кроме уровней debug/trace); конфиг и настройки не логируются; AWG/WG не пишут ключи; ray2sing не печатает профиль. (HC-15)

## Импорт профилей
- Санитизация sing-box-профилей: белый список типов, удаление полей `*_path`, программ Tor, привязки к интерфейсам, `listen_port` и т.п.; `direct` из профиля отбрасывается; AWG/WG-endpoint сохраняется и проверяется; SecurityPolicy с запретом Tor/OpenConnect wrapper/NTP write/Tailscale SSH; raw-конфиг запрещён на мобильных. (HC-03, HC-19)
- `allow-insecure` (по умолчанию выкл.): TLS без проверки сертификата и без пина не попадает в конфиг. (HC-02, HC-24)
- AmneziaWG `.conf` 3.1: булевы on/off, регистр ключей, комментарии, диапазоны, несколько пиров, keepalive-диапазон (и в форке). `vpn://` (AmneziaVPN). (HC-01, HC-11, HC-22, HC-45)
- Hysteria2: `pinSHA256`/`pcs`, `insecure=true`, `mport`, `hop-interval`. ALPN по транспорту; `nosni=0`. XHTTP download-канал не уходит открытым; `xhttpSettings` целиком; REALITY без fp. (HC-02, HC-12, HC-23)
- Вложенные подписки ядро не скачивает (`expand-subscription-links`), при разрешении — только https и публичные адреса; ssconf с таймаутом и лимитом. (HC-16)
- Проверки значений AWG в UAPI (переводы строк, jc/jmin/jmax/s1–s4). (HC-21)

## Утечка B
- `per-app-proxy-mode`/`per-app-proxy-list`/`per-app-strict`: список в TUN и первыми правилами — отбрасывание потоков TUN с неизвестным владельцем и не той стороны списка (Android 10+). В форке — элемент правила `user_id_range`.

## Собственные сокеты ядра на Android (запрос приложения R1, H-02)
- В VPN-режиме на Android `auto_detect_interface` включён: каждый сокет диалеров sing-box (TCP, UDP Hysteria2/TUIC/QUIC/WireGuard/AWG, DNS, `direct`) защищается `VpnService.protect` через платформу и привязывается к сети по умолчанию; Psiphon — через `DeviceBinder`. `Mobile.protectsOwnSockets()` = true: приложение остаётся внутри своего VPN, его запросы идут через туннель, петли нет. В режиме include строгий фильтр не отбрасывает собственный uid приложения.

## Метаданные и поведение
- Мониторинг: 2 проверки одновременно, раз в 30 мин, без direct/block/dns, без геолокации (`ipinfo`), после смены сети — только выбранные; AWG/WG — только при выборе; `default-proxy` по умолчанию `lowest`. В форке: `exclude_types`, `on_demand_types`, `retest_on_network_change`, `disable_ipinfo`, AWG `keepalive_on_use`. (HC-09, HC-10, HC-39)
- DNS: прямой резолвер по умолчанию DoH (Yandex для `ru`, Cloudflare иначе), без открытых запросов к публичным резолверам и без системного DNS при сборке; TTL 5 мин, кэш истекает. «Россия напрямую»: все российские TLD сразу, rule-set'ы через туннель, `rule-set-initial-dir`. (HC-13, HC-14, HC-34, HC-38)
- Случайные адреса TUN (`tun-address-seed`). (HC-32)

## TLS и обход DPI
- Шлюз дозвона (форк `handshake_gate`, ядро — по умолчанию вкл.): ≤ 3 одновременных TLS-рукопожатий и ≥ 450 мс между началами на (IP, SNI).
- Отпечаток по умолчанию — Firefox (для TLS без `fp`); `tls-key-share: classical` для не-REALITY (форк `utls.key_share`); `none/edge/360/qq` → Chrome, `ios` → Safari, `random` без отпечатков 2020 года. (HC-25, HC-27)
- RPC `DpiProbe` — диагностика «16 КБ» с бюджетом соединений.

## Сборка и зависимости
- amneziawg-go v3.1.20261116; go 1.27.4; quic-go v0.59.1; go-chi v5.3.0 (govulncheck: 0 достижимых уязвимостей).
- Android-библиотека без `-gcflags "all=-N -l"`; gomobile v0.1.12; `prepare` = `go mod verify`; `make LEAN=1` — без Tor, OpenConnect, OpenVPN, KCP, Sudoku, Bond, Call, XDrive, v2ray API. (HC-29, HC-30, HC-37)
- Ezytel проверяет сертификат. (HC-20)

## Исправления по отчёту эмулятора sp.2
- Автогруппы `lowest`/`balance` берут членов urltest-группы профиля (`Auto` панели), без UDP-узлов (hysteria, hysteria2, tuic, QUIC, XHTTP поверх HTTP/3, naive QUIC, AWG/WG) при `udp-endpoints-in-auto=false`; узлы вне автогрупп проверяются только при выборе или по запросу (форк `on_demand_tags`). Балансировщик, добавленный горячей перезагрузкой, теперь следует проверкам (форк: подписка на ещё не зарегистрированную группу). (D-05)
- Снимки и дампы горутин — только при debug или теге `with_debug_files`, 0600; `box.log` открывает ядро (форк `log.FileOpener`): ротация 1 МиБ × 2, 0600, строки очищаются как для приложения, включая имена хостов. Отчёт `report-NNN.zip`. (D-10, D-12)
- `DpiProbe`: `upload_path` (поле 12), каждая передача в пределах таймаута стадии, бюджет вызова, ответ всегда с исходом. (D-08)
- gRPC-транспорт: окна приёма 4 МиБ на поток / 16 МиБ на соединение с начала (форк `initial_window_size`); клиент снова дозванивается после `Close` (сброс сети). (таблица узлов sp.2)
