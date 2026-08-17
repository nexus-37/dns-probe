#!/bin/bash
set -uo pipefail

# ============================================================
# dns_probe v4
#
# Скрипт для измерения того, как разные публичные DNS-резолверы
# отвечают на запросы к одним и тем же доменам с разных сетевых точек.
# Использовался в исследовании: https://te-st.org/2026/08/07/dnsdnsdns/
#
# Что скрипт делает архитектурно, зачем нужен каждый блок (killswitch,
# захват TTL/задержки, автоопределение поддержки DoQ и т.д.) и что
# означают поля в выходном JSON — подробно описано в README.md
# в этом же репозитории.
# ============================================================

# ---------- Конфигурация (можно менять через переменные окружения) ----------
REPEATS="${REPEATS:-5}"                 # сколько полных проходов по всем доменам
BASE_DELAY="${BASE_DELAY:-1}"           # базовая пауза между запросами, сек
JITTER_MAX="${JITTER_MAX:-2}"           # + случайная добавка 0..JITTER_MAX сек
EXTERNAL_IP_CHECK_EVERY="${EXTERNAL_IP_CHECK_EVERY:-10}" # внешний ipinfo.io чек раз в N доменов
BASELINE_FILE="${BASELINE_FILE:-}"      # путь к эталонному JSON для diff (опционально)
KDIG_TIMEOUT="${KDIG_TIMEOUT:-3}"

# ---------- Зависимости ----------
for cmd in jq kdig curl bc; do
  if ! command -v $cmd &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y jq knot-dnsutils curl bc
  fi
done

# ---------- Метаданные и стартовый IP ----------
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
INITIAL_IP=$(curl -s -m 5 https://ipinfo.io/ip || echo "unknown")
CITY=$(curl -s -m 5 https://ipinfo.io/city || echo "unknown")
OUTPUT_FILE="probe_v4_$(date +"%Y%m%d_%H%M%S").json"

if [ "$INITIAL_IP" == "unknown" ]; then
    echo "[!] Ошибка: Не удалось определить внешний IP. Проверьте сеть."
    exit 1
fi

# Локальный (дешёвый) src-IP: каким адресом система отправляет пакет к 1.1.1.1.
# Меняется мгновенно при падении/поднятии VPN-туннеля, без единого внешнего запроса.
get_local_src_ip() {
    ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -n1
}
INITIAL_LOCAL_IP=$(get_local_src_ip)

if [ -z "$INITIAL_LOCAL_IP" ]; then
    echo "[!] Не удалось определить локальный src-IP (ip route get). Killswitch будет работать только на внешних чеках."
fi

DOMAIN_COUNTER_FOR_EXTCHECK=0

# Лёгкий чек: локальный src-IP + редкий внешний ipinfo.io
check_ip_lock() {
    if [ -n "$INITIAL_LOCAL_IP" ]; then
        local CUR_LOCAL_IP
        CUR_LOCAL_IP=$(get_local_src_ip)
        if [ -n "$CUR_LOCAL_IP" ] && [ "$CUR_LOCAL_IP" != "$INITIAL_LOCAL_IP" ]; then
            echo ""
            echo "[!!!] CRITICAL: Локальный src-IP изменился ($INITIAL_LOCAL_IP -> $CUR_LOCAL_IP)."
            echo "Вероятно, упал/переподнялся VPN-туннель. Экстренная остановка скрипта."
            exit 1
        fi
    fi

    DOMAIN_COUNTER_FOR_EXTCHECK=$((DOMAIN_COUNTER_FOR_EXTCHECK + 1))
    if (( DOMAIN_COUNTER_FOR_EXTCHECK % EXTERNAL_IP_CHECK_EVERY == 0 )); then
        local CURRENT_IP
        CURRENT_IP=$(curl -s -m 5 https://ipinfo.io/ip)
        if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "$INITIAL_IP" ]; then
            echo ""
            echo "[!!!] CRITICAL: Обнаружено изменение внешнего IP-адреса (redundant check)!"
            echo "Ожидался: $INITIAL_IP, Фактический: $CURRENT_IP"
            exit 1
        fi
    fi
}

# ---------- Baseline (эталон для diff) ----------
declare -A BASELINE_MAP
if [ -n "$BASELINE_FILE" ] && [ -f "$BASELINE_FILE" ]; then
    echo "[*] Загружаю baseline из $BASELINE_FILE для сравнения..."
    while IFS=$'\t' read -r key val; do
        BASELINE_MAP["$key"]="$val"
    done < <(jq -r '.dns_resolution_tests[] | [(.group+"|"+.domain+"|"+.resolver), (.udp_53_answer // .udp_53 // "")] | @tsv' "$BASELINE_FILE" 2>/dev/null)
else
    echo "[*] Baseline не задан — diff-флаги будут выключены (baseline_mismatch: null)."
fi

jq -n \
  --arg time "$START_TIME" \
  --arg ip "$INITIAL_IP" \
  --arg city "$CITY" \
  --argjson repeats "$REPEATS" \
  --arg baseline "$BASELINE_FILE" \
  '{timestamp: $time, node_ip: $ip, city: $city, repeats: $repeats, baseline_file: (if $baseline == "" then null else $baseline end),
    curl_doh_tests: [], dns_resolution_tests: []}' > "$OUTPUT_FILE"

echo "[*] Запуск v4 на узле $INITIAL_IP ($CITY), REPEATS=$REPEATS..."
echo "[*] Killswitch: локальная проверка на каждой итерации + внешняя раз в $EXTERNAL_IP_CHECK_EVERY доменов."

# ---------- Резолверы ----------
# формат: NAME|IP|DOT_SNI|DOH_URL|DOH_SNI|HAS_ENC
RESOLVERS=(
  "NSDI|195.208.4.1|none|none|none|0"
  "Yandex|77.88.8.8|common.dot.dns.yandex.net|https://common.doh.dns.yandex.net/dns-query|common.doh.dns.yandex.net|1"
  "Google|8.8.8.8|dns.google|https://dns.google/dns-query|dns.google|1"
  "Cloudflare|1.1.1.1|cloudflare-dns.com|https://cloudflare-dns.com/dns-query|cloudflare-dns.com|1"
  "Quad9|9.9.9.9|dns.quad9.net|https://dns.quad9.net/dns-query|dns.quad9.net|1"
  "Cisco_Umbrella|208.67.222.222|doh.opendns.com|https://doh.opendns.com/dns-query|doh.opendns.com|1"
  "ControlD|76.76.2.11|freedns.controld.com|https://freedns.controld.com/p0|freedns.controld.com|1"
  "AdGuard|94.140.14.14|dns.adguard-dns.com|https://dns.adguard-dns.com/dns-query|dns.adguard-dns.com|1"
  "NextDNS|45.90.28.0|dns.nextdns.io|https://dns.nextdns.io/dns-query|dns.nextdns.io|1"
  "Mullvad|194.242.2.2|doh.mullvad.net|https://doh.mullvad.net/dns-query|doh.mullvad.net|1"
  "LibreDNS|116.202.176.26|doh.libredns.gr|https://doh.libredns.gr/dns-query|doh.libredns.gr|1"
)

DOMAINS=(
  "Messengers|whatsapp.com"
  "Messengers|telegram.org"
  "Messengers|signal.org"
  "Media|meduza.io"
  "Media|bbc.com"
  "Media|novayagazeta.eu"
  "Tech|protonvpn.com"
  "Tech|te-st.org"
  "Tech|github.com"
  "Reference|microsoft.com"
  "Reference|nvidia.com"
  "Degraded|youtube.com"
  "Degraded|apple.com"
  "LocalRU|ya.ru"
  "LocalRU|vk.ru"
  "CDN|cdnjs.cloudflare.com"
  "CDN|fastly.net"
  "CDN|ajax.googleapis.com"
  "CDN|cdn.jsdelivr.net"
)

# ---------- Проверка поддержки +quic в самом бинарнике kdig (офлайн, без сети) ----------
# ВАЖНО: раньше здесь был сетевой тест против ОДНОГО резолвера (Cloudflare 1.1.1.1),
# и если конкретно ОН не отвечал по DoQ - мы решали, что DoQ "не поддерживается" ВООБЩЕ
# и выключали протокол для ВСЕХ резолверов. Это неверно: отсутствие ответа от Cloudflare
# ничего не говорит о том, есть ли DoQ у AdGuard/NextDNS/etc. Поэтому теперь тут проверяем
# только сам бинарник (умеет ли он в принципе флаг +quic), а реальную доступность DoQ
# на каждом конкретном резолвере пробуем ниже в основном цикле, как и остальные протоколы -
# если сервер не отвечает, это будет TIMEOUT_OR_ERROR именно для него, а не глобальный skip.
QUIC_SUPPORTED=0
if kdig -h 2>&1 | grep -qi '\[no\]quic'; then
    QUIC_SUPPORTED=1
    echo "[*] Бинарник kdig умеет +quic — буду пробовать DoQ на каждом резолвере отдельно."
    echo "[*] (сам факт ответа/неответа конкретного резолвера по DoQ - это данные, а не повод пропускать протокол)"
else
    echo "[*] Бинарник kdig не поддерживает +quic (нужен Knot >=3.2) — DoQ недоступен физически, пропускаю везде."
fi

# ---------- L7 curl-проверка DoH-эндпоинтов (reachability, без реального DNS-запроса) ----------
echo "[*] Этап 1: L7 проверка DoH-эндпоинтов (curl)..."
for res in "${RESOLVERS[@]}"; do
  NAME=$(echo "$res" | cut -d'|' -f1)
  URL=$(echo "$res" | cut -d'|' -f4)
  HAS_ENC=$(echo "$res" | cut -d'|' -f6)

  if [ "$HAS_ENC" -eq 1 ]; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 5 -H "Accept: application/dns-message" "$URL")
    if [ "$HTTP_CODE" = "000" ]; then STATUS="BLOCKED/TIMEOUT"; else STATUS="REACHABLE ($HTTP_CODE)"; fi

    jq --arg name "$NAME" --arg url "$URL" --arg status "$STATUS" \
      '.curl_doh_tests += [{resolver: $name, url: $url, status: $status}]' "$OUTPUT_FILE" > tmp.json && mv tmp.json "$OUTPUT_FILE"
  fi
done

# ---------- Вспомогательная функция: один запрос с TTL + latency ----------
# $1 = доп. флаги kdig (напр. "+tls +tls-hostname=X" или "+quic ...")
# $2 = @IP
# $3 = domain
# echo результат в формате "ANSWER<TAB>TTL<TAB>LATENCY_MS"
run_kdig_timed() {
    local flags="$1" ip="$2" domain="$3"
    local start_ns end_ns elapsed_ms raw answer ttl

    start_ns=$(date +%s%N)
    raw=$(kdig +time="$KDIG_TIMEOUT" $flags @"$ip" "$domain" A +noall +answer 2>&1)
    end_ns=$(date +%s%N)
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    # Строки реального ответа выглядят как: "domain.  TTL  IN  A  1.2.3.4"
    # Если таких строк нет вообще (таймаут, WARNING, ERROR, REFUSED и т.п.) - answer будет пустым,
    # и это единственный критерий провала, без хрупких проверок по ключевым словам.
    answer=$(echo "$raw" | awk '$3=="IN" && $4=="A"{print $5}' | paste -sd "," -)
    ttl=$(echo "$raw" | awk '$3=="IN" && $4=="A"{print $2}' | head -n1)

    if [ -z "$answer" ]; then
        echo -e "TIMEOUT_OR_ERROR\t0\t$elapsed_ms"
    else
        echo -e "$answer\t${ttl:-0}\t$elapsed_ms"
    fi
}

# Node-id через CHAOS TXT (best-effort, не у всех резолверов работает)
get_node_id() {
    local ip="$1"
    local id
    id=$(kdig +time=2 +short -c CH -t TXT id.server @"$ip" 2>/dev/null | tr -d '"')
    if [ -z "$id" ]; then
        id=$(kdig +time=2 +short -c CH -t TXT hostname.bind @"$ip" 2>/dev/null | tr -d '"')
    fi
    [ -z "$id" ] && id="unknown"
    echo "$id"
}

# ---------- Этап 2: основной цикл резолвинга ----------
echo "[*] Этап 2: Резолвинг доменов (UDP / DoT / DoH / DoQ), $REPEATS проход(ов)..."

for (( PASS=1; PASS<=REPEATS; PASS++ )); do
  echo "[*] === Проход $PASS/$REPEATS ==="
  CURRENT_GROUP=""

  for dom_entry in "${DOMAINS[@]}"; do
    GROUP=$(echo "$dom_entry" | cut -d'|' -f1)
    DOMAIN=$(echo "$dom_entry" | cut -d'|' -f2)

    # Killswitch на каждый домен внутри прохода (локальный чек дешёвый — не жалко)
    check_ip_lock

    for res in "${RESOLVERS[@]}"; do
      NAME=$(echo "$res" | cut -d'|' -f1)
      IP=$(echo "$res" | cut -d'|' -f2)
      DOT_SNI=$(echo "$res" | cut -d'|' -f3)
      DOH_URL=$(echo "$res" | cut -d'|' -f4)
      DOH_SNI=$(echo "$res" | cut -d'|' -f5)
      HAS_ENC=$(echo "$res" | cut -d'|' -f6)

      echo "  [$PASS/$REPEATS] $DOMAIN via $NAME..."

      # UDP 53
      IFS=$'\t' read -r UDP_ANSWER UDP_TTL UDP_MS <<< "$(run_kdig_timed "" "$IP" "$DOMAIN")"

      NODE_ID="unknown"

      if [ "$HAS_ENC" -eq 1 ]; then
        # DoT 853
        IFS=$'\t' read -r DOT_ANSWER DOT_TTL DOT_MS <<< "$(run_kdig_timed "+tls +tls-hostname=$DOT_SNI" "$IP" "$DOMAIN")"

        # DoH 443
        DOH_PATH=$(echo "$DOH_URL" | sed -E 's|https://[^/]+||')
        IFS=$'\t' read -r DOH_ANSWER DOH_TTL DOH_MS <<< "$(run_kdig_timed "+https=$DOH_PATH +tls-hostname=$DOH_SNI" "$IP" "$DOMAIN")"

        # DoQ 853 (если поддерживается локально)
        if [ "$QUIC_SUPPORTED" -eq 1 ]; then
          IFS=$'\t' read -r DOQ_ANSWER DOQ_TTL DOQ_MS <<< "$(run_kdig_timed "+quic -p 853 +tls-hostname=$DOT_SNI" "$IP" "$DOMAIN")"
        else
          DOQ_ANSWER="NOT_TESTED_LOCAL"; DOQ_TTL=0; DOQ_MS=0
        fi

        NODE_ID=$(get_node_id "$IP")
      else
        DOT_ANSWER="NOT_SUPPORTED"; DOT_TTL=0; DOT_MS=0
        DOH_ANSWER="NOT_SUPPORTED"; DOH_TTL=0; DOH_MS=0
        DOQ_ANSWER="NOT_SUPPORTED"; DOQ_TTL=0; DOQ_MS=0
      fi

      # Baseline diff (сверяем UDP-ответ с эталоном, как самый частый протокол сравнения)
      BASELINE_KEY="${GROUP}|${DOMAIN}|${NAME}"
      MISMATCH="null"
      if [ -n "$BASELINE_FILE" ] && [ -f "$BASELINE_FILE" ]; then
        BASE_VAL="${BASELINE_MAP[$BASELINE_KEY]:-}"
        if [ -n "$BASE_VAL" ] && [ "$UDP_ANSWER" != "TIMEOUT_OR_ERROR" ]; then
          if [ "$BASE_VAL" == "$UDP_ANSWER" ]; then MISMATCH="false"; else MISMATCH="true"; fi
        fi
      fi

      jq --arg grp "$GROUP" --arg dom "$DOMAIN" --arg res_name "$NAME" --argjson pass "$PASS" \
         --arg udp "$UDP_ANSWER" --argjson udp_ttl "${UDP_TTL:-0}" --argjson udp_ms "${UDP_MS:-0}" \
         --arg dot "$DOT_ANSWER" --argjson dot_ttl "${DOT_TTL:-0}" --argjson dot_ms "${DOT_MS:-0}" \
         --arg doh "$DOH_ANSWER" --argjson doh_ttl "${DOH_TTL:-0}" --argjson doh_ms "${DOH_MS:-0}" \
         --arg doq "$DOQ_ANSWER" --argjson doq_ttl "${DOQ_TTL:-0}" --argjson doq_ms "${DOQ_MS:-0}" \
         --arg node_id "$NODE_ID" \
         --argjson mismatch "$MISMATCH" \
        '.dns_resolution_tests += [{
          pass: $pass,
          group: $grp,
          domain: $dom,
          resolver: $res_name,
          node_id: $node_id,
          udp_53: {answer: $udp, ttl: $udp_ttl, latency_ms: $udp_ms},
          dot_853: {answer: $dot, ttl: $dot_ttl, latency_ms: $dot_ms},
          doh_443: {answer: $doh, ttl: $doh_ttl, latency_ms: $doh_ms},
          doq_853: {answer: $doq, ttl: $doq_ttl, latency_ms: $doq_ms},
          baseline_mismatch: $mismatch
        }]' "$OUTPUT_FILE" > tmp.json && mv tmp.json "$OUTPUT_FILE"

      # Пауза между запросами: база + джиттер, чтобы не бить резолвер/тарг ровными интервалами
      SLEEP_TIME=$(echo "scale=2; $BASE_DELAY + ($RANDOM % ($JITTER_MAX * 100 + 1)) / 100" | bc -l 2>/dev/null)
      # Доп. защита: если bc всё равно вернул пустую строку (например, bc не установлен
      # и в контейнере нет apt-доступа) - откатываемся на целочисленный BASE_DELAY,
      # чтобы sleep никогда не получил пустой аргумент.
      if [ -z "$SLEEP_TIME" ]; then
        SLEEP_TIME="$BASE_DELAY"
      fi
      sleep "$SLEEP_TIME"
    done
  done
done

echo "[+] Готово! Результаты: $OUTPUT_FILE"
