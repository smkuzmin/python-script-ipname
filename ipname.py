#!/usr/bin/env python3

r"""
IPName v1.5 - IPv4 Resolver

Reads IPv4 addresses, networks and hostnames from STDIN, resolves them
to 'ip # name' format via DNS and WHOIS lookups, and outputs the list to STDOUT in order of appearance.

FEATURES:
  - Comments (lines starting with #) are passed through unchanged
  - Invalid lines are printed as-is
  - Pure Python WHOIS client (no external whois command required)
  - Uses DNS and WHOIS for resolution only if no comment present (may be slow)
  - Normalizes subnet masks to CIDR prefix (e.g., /255.255.255.0 → /24)
  - Single IP addresses output without /32 prefix

INPUT FORMAT:
  77.88.55.88               # Single IP address
  77.88.55.0/24             # Network with CIDR prefix
  77.88.55.0/255.255.255.0  # Network with subnet mask
  yandex.ru                 # Hostname

OUTPUT FORMAT:
  77.88.55.88        # yandex.ru
  77.88.55.0/24      # YANDEX-77-88-55-0
  77.88.55.0/24      # YANDEX-77-88-55-0
  5.255.255.77       # yandex.ru
  77.88.44.55        # yandex.ru
  77.88.55.88        # yandex.ru

USAGE:
  cat input_file | ipname
  ipname < file.lst
  ipname < file.lst > output.lst
"""

import sys
import re
import socket
from ipaddress import ip_network, IPv4Address

# Валидация
# Проверка: цифра и диапазон 0-255
V = lambda s: s.isdigit() and 0 <= int(s) <= 255
# Проверка IPv4: 4 октета, все валидны, без ведущих нулей (кроме "0")
ip_ok = lambda s: len(s.split('.')) == 4 and all(V(o) for o in s.split('.')) and not any(o != '0' and o.startswith('0') for o in s.split('.'))
# Проверка маски: либо число 0-32, либо валидный IP
mask_ok = lambda s: s.isdigit() and 0 <= int(s) <= 32 or ip_ok(s)
# Проверка CIDR: есть "/", левая часть - валидный IP, правая - валидная маска
net_ok = lambda s: '/' in s and ip_ok(s.split('/')[0]) and mask_ok(s.split('/')[1])
# Проверка хоста: не пустой, без "..", "--", "-.", ".-", начинается и заканчивается на [a-zA-Z0-9]
host_ok = lambda s: s and '..' not in s and '--' not in s and '-.' not in s and '.-' not in s and re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$', s)

# DNS
def rdns(ip, short=False):
    """Обратный DNS: IP -> имя хоста"""
    try:
        h = socket.gethostbyaddr(ip)[0].lower()
        return h.split('.')[0] if short else h
    except:
        return None

def fwd(host):
    """Прямой DNS: имя хоста -> список IP"""
    try:
        return sorted(set(r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET)),
                     key=lambda x: tuple(map(int, x.split('.'))))
    except:
        return []

# WHOIS (чистый Python, порт 43)
def whois_query(query, server, timeout=3):
    """Простой WHOIS-клиент через TCP-порт 43"""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + '\r\n').encode('ascii'))
            response = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:  # ограничение размера ответа
                    break
            return response.decode('utf-8', errors='ignore')
    except:
        return None

def field_val(response, field_name):
    """Извлечь первое значение поля (как grep -im1 + sed в bash)"""
    if not response:
        return None
    for ln in response.split('\n'):
        ln_lower = ln.lower()
        if ln_lower.startswith(field_name.lower() + ':'):
            # Извлечь значение после двоеточия, убрать пробелы и спецсимволы
            val = ln.split(':', 1)[1].strip()
            # Оставить только буквы, цифры, пробел, точку, подчёркивание, слэш, дефис
            val = re.sub(r'[^a-zA-Z0-9 _./-]', '', val)
            if val and val.lower() not in ('na', 'none', '-'):
                return val
    return None

def whois_desc(cidr):
    """
    Получить описание со строгим приоритетом (как в оригинальном bash):
    1. netname из RIPE
    2. descr из RADB
    3. origin из RADB
    """
    ip = cidr.split('/')[0]

    # 1. Пробуем RIPE для netname
    response = whois_query(ip, 'whois.ripe.net')
    desc = field_val(response, 'netname')
    if desc:
        return desc

    # 2. Пробуем RADB для descr
    response = whois_query(ip, 'whois.radb.net')
    desc = field_val(response, 'descr')
    if desc:
        return desc

    # 3. Пробуем RADB для origin
    desc = field_val(response, 'origin')
    if desc:
        return desc

    return None

# Нормализация сети
def normalize_net(tok):
    """
    Привести IP/сеть к каноническому формату вывода:
    - 8.8.8.8/32            -> 8.8.8.8    (без /32)
    - 8.8.8.0/255.255.255.0 -> 8.8.8.0/24 (CIDR)
    - 8.8.8.0/24            -> 8.8.8.0/24 (без изменений)
    """
    try:
        net = ip_network(tok, strict=False)
        # Одиночные хосты выводим без /32
        if net.prefixlen == 32:
            return str(net.network_address)
        return str(net)
    except:
        return tok  # возврат оригинала при ошибке

# Форматирование вывода
def fmt(ip, name=''):
    """Вывести строку в фиксированном формате: '%-18s # %s'"""
    print(f"{ip:<18} # {name}")

# Парсинг строки
def parse_line(line):
    """
    Разобрать строку ввода. Возвращает:
    - (токен, комментарий, исходная_строка) если токен валиден
    - (None, None, исходная_строка) для комментариев и пустых строк

    Правило для комментария (строго по '#'):
    - Только формат 'токен # текст' считается комментарием.
    - Если '#' отсутствует - текст после токена игнорируется, выполняется резолв.
    - Если '#' есть, но после него пусто или только пробелы - резолв выполняется.
    """
    raw = line.rstrip('\n\r')
    stripped = raw.strip()

    # Пустые строки и строки-комментарии пропускаем без изменений
    if not stripped or stripped.startswith('#'):
        return None, None, raw

    # Ищем явный разделитель '#'
    if '#' in raw:
        parts = raw.split('#', 1)
        tok = parts[0].strip()
        # Комментарий считается присутствующим только если после '#' есть непустой текст
        comment = parts[1].strip() if parts[1].strip() else ''
    else:
        # Нет '#' - берём первый токен как адрес, остальное игнорируем, резолв будет
        parts = raw.split(None, 1)
        tok = parts[0].strip() if parts else ''
        comment = ''  # пустой комментарий → резолв

    if not tok:
        return None, None, raw

    return tok, comment, raw

# Точка входа
# Показать справку при -h / --help или запуске без stdin
if '-h' in sys.argv or '--help' in sys.argv or sys.stdin.isatty():
    print(__doc__)
    sys.exit(0)

# Основной цикл обработки stdin
for line in sys.stdin:
    tok, existing_comment, original = parse_line(line)

    # Комментарии и пустые строки выводим как есть
    if tok is None:
        print(original)
        continue

    # Резолв НЕ делаем ТОЛЬКО если есть формат: токен # непустой текст
    # Во всех остальных случаях - выполняем резолв через DNS/WHOIS
    if existing_comment:
        fmt(normalize_net(tok), existing_comment)
        continue

    # Если комментария нет - пробуем резолвить через DNS/WHOIS
    if ip_ok(tok):
        if h := rdns(tok):
            fmt(normalize_net(tok), h)
            continue
        if d := whois_desc(tok):
            fmt(normalize_net(tok), d)
            continue
        fmt(normalize_net(tok))  # без комментария
        continue

    if net_ok(tok):
        if d := whois_desc(tok):
            fmt(normalize_net(tok), d)
            continue
        fmt(normalize_net(tok))  # без комментария
        continue

    if host_ok(tok):
        ips = fwd(tok)
        if ips:
            for ip in ips:
                fmt(ip, tok)
            continue
        # Хост не резолвится - выводим исходную строку как есть
        print(original)
        continue

    # Некорректная строка - выводим как есть
    print(original)
