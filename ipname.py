#!/usr/bin/env python3

r"""
IPName v1.11 - IPv4 Resolver

Reads IPv4 addresses, networks and hostnames from STDIN, resolves them
to 'ip # name' format via DNS and WHOIS lookups, and outputs the list to STDOUT in order of appearance.

FEATURES:
  - Comments (lines starting with #) are passed through unchanged
  - DNS and WHOIS resolution is performed only when no explicit comment is provided for IPs/networks
  - Normalizes subnet masks to CIDR notation (e.g., /255.255.255.0 -> /24)
  - Single IP addresses are output without the /32 suffix
  - Custom DNS servers support

INPUT FORMAT:
  77.88.55.88                 Single IP address
  77.88.55.0/24               Network with CIDR prefix
  77.88.55.0/255.255.255.0    Network with subnet mask
  yandex.ru                   Hostname

OUTPUT FORMAT:
  77.88.55.88        # yandex.ru
  77.88.55.0/24      # YANDEX-77-88-55-0
  77.88.55.0/24      # YANDEX-77-88-55-0
  5.255.255.77       # yandex.ru
  77.88.44.55        # yandex.ru
  77.88.55.88        # yandex.ru

USAGE:
  cat infile.lst | ipname [OPTIONS]
  ipname [OPTIONS] < infile.lst > outfile.lst

OPTIONS:
  -r, --resolved-only        Output only successfully resolved entries
  -w, --resolved-wan-only    Output only public (WAN) resolved entries
  -l, --resolved-lan-only    Output only private (LAN) resolved entries
  -d, --dns=SERVERS          Custom DNS servers (comma-separated, e.g. 8.8.8.8,1.1.1.1)
"""

import sys
import re
import socket
import struct
import random
from ipaddress import ip_network, IPv4Address, IPv4Network


# Минимальный DNS-клиент (чистый Python, без зависимостей)
def _dns_query(qname, qtype, nameservers, timeout=3):
    """
    Отправить DNS-запрос к указанным серверам.
    qtype: 1 = A, 12 = PTR
    Возвращает список ответов (строки) или None при ошибке.
    """
    # Формируем заголовок
    txn_id = random.randint(0, 65535)
    flags = 0x0100  # стандартный рекурсивный запрос
    header = struct.pack('>HHHHHH', txn_id, flags, 1, 0, 0, 0)
    
    # Формируем вопрос
    question = b''
    for label in qname.rstrip('.').split('.'):
        question += bytes([len(label)]) + label.encode('ascii')
    question += b'\x00' + struct.pack('>HH', qtype, 1)  # тип, класс=IN
    
    packet = header + question
    
    # Пробуем сервера по очереди
    for ns in nameservers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (ns, 53))
            data, _ = sock.recvfrom(512)  # UDP-ответ обычно <=512 байт
            sock.close()
            
            # Парсим ответ (минимально: только ответы на наш вопрос)
            # Пропускаем заголовок и вопрос
            offset = 12  # заголовок
            # Пропускаем вопрос
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 5  # null-байт + 2 байта тип + 2 байта класс
            
            # Читаем ответы
            answers = []
            ancount = struct.unpack('>H', data[6:8])[0]
            for _ in range(ancount):
                # Пропускаем имя (может быть сжатие)
                while True:
                    if offset >= len(data):
                        break
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    elif (length & 0xC0) == 0xC0:  # сжатие
                        offset += 2
                        break
                    else:
                        offset += length + 1
                
                if offset + 10 > len(data):
                    break
                atype, aclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset+10])
                offset += 10
                
                if atype == 1 and qtype == 1:  # A-запись
                    if rdlen == 4:
                        ip = '.'.join(str(b) for b in data[offset:offset+4])
                        answers.append(ip)
                elif atype == 12 and qtype == 12:  # PTR-запись
                    # Парсим доменное имя в ответе
                    rdata_offset = offset
                    name_parts = []
                    while True:
                        if rdata_offset >= len(data):
                            break
                        length = data[rdata_offset]
                        if length == 0:
                            break
                        elif (length & 0xC0) == 0xC0:
                            # Для простоты игнорируем сжатие в ответах PTR
                            break
                        else:
                            rdata_offset += 1
                            name_parts.append(data[rdata_offset:rdata_offset+length].decode('ascii', errors='ignore'))
                            rdata_offset += length
                    if name_parts:
                        answers.append('.'.join(name_parts).rstrip('.').lower())
                
                offset += rdlen
            
            if answers:
                return answers
        except:
            continue
    return None


def _rdns_custom(ip, nameservers, short=False):
    """Обратный DNS через кастомные сервера (PTR-запрос)"""
    # Формируем reverse-имя: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
    rev_name = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
    results = _dns_query(rev_name, 12, nameservers)  # 12 = PTR
    if results:
        h = results[0]
        return h.split('.')[0] if short else h
    return None


def _fwd_custom(host, nameservers):
    """Прямой DNS через кастомные сервера (A-запрос)"""
    results = _dns_query(host, 1, nameservers)  # 1 = A
    if results:
        return sorted(set(results), key=lambda x: tuple(map(int, x.split('.'))))
    return []

def main():
    # Парсим аргументы командной строки
    resolved_only = False        # флаг: выводить только отрезолвленные записи
    resolved_lan_only = False    # флаг: выводить только отрезолвленные записи с адресами из LAN
    resolved_wan_only = False    # флаг: выводить только отрезолвленные записи с адресами из WAN
    custom_dns = None            # список кастомных DNS-серверов
    args = sys.argv[1:]

    # Используем while-цикл для поддержки аргументов вида "-d 8.8.8.8" (через пробел)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-r', '--resolved-only'):
            resolved_only = True
        elif arg in ('-l', '--resolved-lan-only'):
            resolved_lan_only = True
        elif arg in ('-w', '--resolved-wan-only'):
            resolved_wan_only = True
        elif arg == '-d':
            # Формат через пробел: -d 8.8.8.8,1.1.1.1
            if i + 1 < len(args):
                i += 1
                servers = args[i]
                custom_dns = [s.strip() for s in servers.split(',') if s.strip()]
            else:
                print("Error: Option -d requires a server argument", file=sys.stderr)
                sys.exit(1)
        elif arg.startswith('--dns='):
            # Формат через знак равно: --dns=8.8.8.8,1.1.1.1
            servers = arg.split('=', 1)[1]
            if servers:
                custom_dns = [s.strip() for s in servers.split(',') if s.strip()]
            else:
                print("Error: Option --dns requires a server value", file=sys.stderr)
                sys.exit(1)
        elif arg in ('-h', '--help'):
            print(__doc__, file=sys.stderr)
            sys.exit(0)
        else:
            print(f"Error: Invalid option: {arg}", file=sys.stderr)
            sys.exit(1)
        i += 1

    # Валидация кастомных DNS-серверов
    if custom_dns:
        for dns_ip in custom_dns:
            parts = dns_ip.split('.')
            if not (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)):
                print(f"Error: Invalid DNS server IP: {dns_ip}", file=sys.stderr)
                sys.exit(1)

    # Проверка на взаимоисключающие флаги (только один режим может быть активен)
    if sum([resolved_only, resolved_lan_only, resolved_wan_only]) > 1:
        print("Error: Options -r, -l and -w are mutually exclusive", file=sys.stderr)
        sys.exit(1)

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
        # Если есть кастомные DNS - используем встроенный клиент
        if custom_dns:
            result = _rdns_custom(ip, custom_dns, short)
            if result:
                return result
        # Иначе - системный резолвер
        try:
            h = socket.gethostbyaddr(ip)[0].lower()
            return h.split('.')[0] if short else h
        except:
            return None

    def fwd(host):
        """Прямой DNS: имя хоста -> список IP"""
        # Если есть кастомные DNS - используем встроенный клиент
        if custom_dns:
            result = _fwd_custom(host, custom_dns)
            if result:
                return result
        # Иначе - системный резолвер
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

    # Вспомогательная функция для фильтрации по WAN/LAN
    def filter_wan_lan(obj):
        """Проверка: должен ли объект пройти фильтр WAN/LAN"""
        if resolved_wan_only and not obj.is_global:
            return False
        if resolved_lan_only and obj.is_global:
            return False
        return True

    # Основной цикл обработки stdin
    for line in sys.stdin:
        tok, existing_comment, original = parse_line(line)

        # Комментарии и пустые строки выводим как есть
        if tok is None:
            print(original)
            continue

        # Если комментария нет - пробуем резолвить через DNS/WHOIS
        if ip_ok(tok):
            # IP с комментарием: выводим как есть, резолв НЕ делаем
            if existing_comment:
                fmt(normalize_net(tok), existing_comment)
                continue
            
            resolved = False
            if h := rdns(tok):
                # Фильтрация WAN/LAN для IP
                try:
                    ip_obj = IPv4Address(tok)
                    if filter_wan_lan(ip_obj):
                        fmt(normalize_net(tok), h)
                        resolved = True
                except:
                    pass
            elif d := whois_desc(tok):
                try:
                    ip_obj = IPv4Address(tok)
                    if filter_wan_lan(ip_obj):
                        fmt(normalize_net(tok), d)
                        resolved = True
                except:
                    pass
            
            if not resolved and (resolved_only or resolved_lan_only or resolved_wan_only):
                continue  # скрыть неотрезолвленные в режимах --resolved-*
            elif not resolved:
                fmt(normalize_net(tok))  # без комментария
            continue

        if net_ok(tok):
            # Сеть с комментарием: выводим как есть, резолв НЕ делаем
            if existing_comment:
                fmt(normalize_net(tok), existing_comment)
                continue
            
            resolved = False
            if d := whois_desc(tok):
                try:
                    net_obj = IPv4Network(tok, strict=False)
                    if filter_wan_lan(net_obj):
                        fmt(normalize_net(tok), d)
                        resolved = True
                except:
                    pass
            
            if not resolved and (resolved_only or resolved_lan_only or resolved_wan_only):
                continue  # скрыть неотрезолвленные в режимах --resolved-*
            elif not resolved:
                fmt(normalize_net(tok))  # без комментария
            continue

        if host_ok(tok):
            # Хостнеймы РЕЗОЛВИМ ВСЕГДА, даже если есть комментарий
            ips = fwd(tok)
            if ips:
                for ip in ips:
                    # Фильтрация WAN/LAN для IP из хоста
                    try:
                        ip_obj = IPv4Address(ip)
                        if filter_wan_lan(ip_obj):
                            fmt(ip, tok)
                    except:
                        fmt(ip, tok)  # если ошибка валидации - выводим как есть
                continue
            # Хост не резолвится
            if resolved_only or resolved_lan_only or resolved_wan_only:
                continue  # скрыть неотрезолвленные в режимах --resolved-*
            else:
                print(original)  # выводим исходную строку как есть
            continue

        # Некорректная строка
        if resolved_only or resolved_lan_only or resolved_wan_only:
            continue  # скрыть неотрезолвленные в режимах --resolved-*
        else:
            print(original)  # выводим как есть


# Точка входа
if __name__ == '__main__':
    # Показываем справку при вызове с -h или --help, или если запущен без перенаправления ввода
    if sys.stdin.isatty() or '-h' in sys.argv or '--help' in sys.argv:
        print(__doc__, file=sys.stderr)
        sys.exit(0)

    # Обрабатываем прерывание без вывода ошибки
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
