import re
import time
import ipaddress
import hashlib
import secrets
import base64
import hmac
import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from collections import defaultdict
import logging
from functools import lru_cache
import json
import asyncio
from contextlib import contextmanager
import random
import string
import math

logger = logging.getLogger(__name__)


class WAFRule:
    """
    Представляет одно правило WAF.
    Содержит скомпилированное регулярное выражение, метаданные правила
    и счётчик срабатываний.
    """

    def __init__(self, rule_id: str, pattern: str, severity: str = "medium",
                 description: str = "", action: str = "block"):
        """
        :param rule_id: Уникальный идентификатор правила (например, SQLI-001)
        :param pattern: Строка регулярного выражения (будет скомпилирована с флагом re.IGNORECASE)
        :param severity: Критичность ('low', 'medium', 'high', 'critical')
        :param description: Человеко-читаемое описание угрозы
        :param action: Действие при срабатывании ('block', 'alert', 'log')
        """
        self.rule_id = rule_id
        # Пытаемся скомпилировать паттерн; при ошибке заменяем на паттерн, который никогда не сработает
        try:
            self.pattern = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.pattern = re.compile(r"(?!)", re.IGNORECASE)  # никогда не совпадает
            logger.error(f"Ошибка компиляции правила {rule_id}: {pattern}")

        self.severity = severity
        self.description = description
        self.action = action
        self.trigger_count = 0          # сколько раз правило сработало
        self.last_triggered = None       # дата последнего срабатывания


class WAFSignature:
    """
    Содержит предопределённые наборы сигнатур для разных классов атак.
    Метод get_all_rules() собирает все правила в единый список объектов WAFRule.
    """

    # Паттерны SQL-инъекций: (регулярное выражение, краткое описание)
    SQL_INJECTION_PATTERNS = [
        (r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|SET|WHERE|VALUES)\b)", "SQL Injection"),
        (r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", "SQL Boolean Injection"),
        (r"(\b(SLEEP|WAITFOR|BENCHMARK)\(.*\))", "SQL Time-based Injection"),
        (r"(\b(UNION\s+ALL\s+SELECT)\b)", "Union SQL Injection"),
        (r"(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)", "SQL File Operations"),
        (r"(--|#|/\*|\*/|;)", "SQL Comment Injection"),
        (r"(\b(XPATH|CONCAT|GROUP_CONCAT)\b.*\()", "SQL Function Injection"),
        (r"(\b(CASE|WHEN|THEN|END)\b.*\b(WHEN|THEN)\b)", "SQL Conditional Injection"),
        (r"(\b(CHAR|ASCII|BIN|HEX)\b.*\()", "SQL Encoding Functions"),
        (r"(\b(IF|ELSE|ENDIF)\b.*\()", "SQL Conditional Functions"),
    ]

    # Паттерны XSS-атак
    XSS_PATTERNS = [
        (r"(<script.*?>.*?</script>)", "Script Tag XSS"),
        (r"(javascript:)", "JavaScript Protocol XSS"),
        (r"(on\w+\s*=)", "Event Handler XSS"),
        (r"(alert\(.*\))", "Alert XSS"),
        (r"(document\.(cookie|location|domain|referrer))", "Document Object XSS"),
        (r"(window\.(location|open))", "Window Object XSS"),
        (r"(eval\(.*\))", "Eval XSS"),
        (r"(setTimeout|setInterval).*\(.*\)", "Timer XSS"),
        (r"(<iframe.*?>.*?</iframe>)", "IFrame XSS"),
        (r"(<img.*?src.*?=.*?javascript:)", "IMG Tag XSS"),
        (r"(<svg.*?onload.*?=)", "SVG XSS"),
        (r"(<body.*?onload.*?=)", "Body Tag XSS"),
        (r"(<input.*?onfocus.*?=)", "Input Tag XSS"),
        (r"(<marquee.*?onstart.*?=)", "Marquee Tag XSS"),
        (r"(<details.*?ontoggle.*?=)", "Details Tag XSS"),
        (r"(<select.*?onchange.*?=)", "Select Tag XSS"),
    ]

    # Паттерны Path Traversal (обхода директорий)
    PATH_TRAVERSAL_PATTERNS = [
        (r"(\.\./|\.\.\\)", "Directory Traversal"),
        (r"(/etc/passwd|/etc/shadow|/etc/hosts)", "System File Access"),
        (r"(c:\\windows\\system32\\config\\sam)", "Windows SAM File"),
        (r"(\.\.%2f|\.\.%5c)", "Encoded Directory Traversal"),
        (r"(%00|%0a|%0d)", "Null Byte Injection"),
        (r"(/proc/self/environ|/proc/self/cmdline)", "Proc Filesystem Access"),
        (r"(\.git/|\.svn/|\.hg/)", "Version Control Files"),
        (r"(\.env|\.htaccess|\.htpasswd)", "Configuration Files"),
        (r"(php://filter|zip://|phar://)", "PHP Wrappers"),
        (r"(file://|ftp://|gopher://)", "Dangerous Protocols"),
    ]

    # Паттерны Command Injection
    COMMAND_INJECTION_PATTERNS = [
        (r"(;\s*(ls|dir|cat|more|less|head|tail|ps|netstat|ifconfig|ipconfig))", "Command Injection"),
        (r"(\|\s*(ls|dir|cat|more|less|head|tail))", "Pipe Command Injection"),
        (r"(&&\s*(ls|dir|cat|more|less|head|tail))", "AND Command Injection"),
        (r"(\|\|\s*(ls|dir|cat|more|less|head|tail))", "OR Command Injection"),
        (r"(\$(\(.*\)|\{.*\}))", "Bash Command Substitution"),
        (r"(`.*`)", "Backtick Command Execution"),
        (r"(wget\s+|curl\s+|nc\s+|ncat\s+|telnet\s+)", "Network Tools"),
        (r"(python\s+|perl\s+|ruby\s+|php\s+)", "Script Execution"),
        (r"(base64\s+-d|base64\s+-decode)", "Base64 Decode Command"),
        (r"(sh\s+-i|bash\s+-i|zsh\s+-i)", "Reverse Shell"),
    ]

    # Паттерны File Inclusion (LFI/RFI)
    FILE_INCLUSION_PATTERNS = [
        (r"(include\(.*\)|require\(.*\)|include_once\(.*\)|require_once\(.*\))", "File Inclusion"),
        (r"(\.\./\.\./\.\./)", "Multiple Directory Traversal"),
        (r"(http://|https://|ftp://).*(\.php|\.asp|\.aspx|\.jsp)", "Remote File Inclusion"),
        (r"(php://input|data://)", "PHP Stream Wrappers"),
        (r"(expect://|ssh2://)", "Dangerous PHP Wrappers"),
        (r"(\./\./\./)", "Relative Path Traversal"),
    ]

    # Паттерны SSRF
    SSRF_PATTERNS = [
        (r"(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)", "Localhost Access"),
        (r"(169\.254\.169\.254|metadata\.google\.internal)", "Cloud Metadata"),
        (r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)", "Private IP Range"),
        (r"(file://|gopher://|dict://)", "Dangerous URL Schemes"),
        (r"(admin|internal|backend|management)", "Internal Service Names"),
    ]

    # Паттерны XXE
    XXE_PATTERNS = [
        (r"(<!DOCTYPE.*\[.*\])", "XML DOCTYPE Declaration"),
        (r"(<!ENTITY.*SYSTEM.*>)", "XML External Entity"),
        (r"(file:///|http://|ftp://).*ENTITY", "External Entity Reference"),
        (r"(XXE|XML External Entity)", "XXE Keyword"),
        (r"(<!ELEMENT|<!ATTLIST)", "XML Schema Elements"),
    ]

    # Паттерны API Abuse
    API_ABUSE_PATTERNS = [
        (r"(/api/.*(admin|delete|drop|truncate))", "Admin API Abuse"),
        (r"(/v[0-9]+/.*)", "API Version Enumeration"),
        (r"(swagger|openapi|api-docs)", "API Documentation"),
        (r"(\.json|\.xml|\.yaml|\.yml)", "API Data Formats"),
        (r"(limit=1000|limit=9999)", "Large Result Set"),
        (r"(offset=10000|page=1000)", "Deep Pagination"),
    ]

    # Паттерны сканеров и ботов
    SCANNER_PATTERNS = [
        (r"(nmap|nikto|sqlmap|metasploit|nessus|acunetix|w3af|skipfish|burpsuite|zap)", "Security Scanner"),
        (r"(dirb|gobuster|ffuf|wfuzz|dirbuster)", "Directory Brute Force"),
        (r"(wp-admin|wp-login|wp-content)", "WordPress Scanner"),
        (r"(phpmyadmin|adminer|mysql-admin)", "Database Admin Scanner"),
        (r"(\.git/HEAD|\.svn/entries|\.hg/store)", "Version Control Scanner"),
        (r"(robots\.txt|sitemap\.xml|crossdomain\.xml)", "Crawler Directives"),
        (r"(\.DS_Store|Thumbs\.db|desktop\.ini)", "OS Metadata Files"),
    ]

    @classmethod
    def get_all_rules(cls) -> List[WAFRule]:
        """
        Собирает все сигнатуры в единый список объектов WAFRule.
        Каждой сигнатуре присваивается уникальный идентификатор и уровень критичности.
        """
        rules = []
        rule_counter = 1

        # SQL Injection
        for pattern, desc in cls.SQL_INJECTION_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"SQLI-{rule_counter:03d}",
                pattern=pattern,
                severity="critical",
                description=f"SQL Injection: {desc}",
                action="block"
            ))
            rule_counter += 1

        # XSS
        for pattern, desc in cls.XSS_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"XSS-{rule_counter:03d}",
                pattern=pattern,
                severity="high",
                description=f"XSS Attack: {desc}",
                action="block"
            ))
            rule_counter += 1

        # Path Traversal
        for pattern, desc in cls.PATH_TRAVERSAL_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"PT-{rule_counter:03d}",
                pattern=pattern,
                severity="high",
                description=f"Path Traversal: {desc}",
                action="block"
            ))
            rule_counter += 1

        # Command Injection
        for pattern, desc in cls.COMMAND_INJECTION_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"CI-{rule_counter:03d}",
                pattern=pattern,
                severity="critical",
                description=f"Command Injection: {desc}",
                action="block"
            ))
            rule_counter += 1

        # File Inclusion
        for pattern, desc in cls.FILE_INCLUSION_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"FI-{rule_counter:03d}",
                pattern=pattern,
                severity="high",
                description=f"File Inclusion: {desc}",
                action="block"
            ))
            rule_counter += 1

        # SSRF
        for pattern, desc in cls.SSRF_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"SSRF-{rule_counter:03d}",
                pattern=pattern,
                severity="medium",
                description=f"SSRF Attempt: {desc}",
                action="alert"
            ))
            rule_counter += 1

        # XXE
        for pattern, desc in cls.XXE_PATTERNS:
            rules.append(WAFRule(
                rule_id=f"XXE-{rule_counter:03d}",
                pattern=pattern,
                severity="high",
                description=f"XXE Attack: {desc}",
                action="block"
            ))
            rule_counter += 1

        # Остальные категории (API Abuse, Scanner) можно добавить аналогично при необходимости
        # Здесь они пропущены для краткости, но могут быть добавлены.

        return rules


class WAFEngine:
    """
    Основной движок WAF.
    Выполняет анализ запросов, проверку IP по чёрному/белому спискам,
    rate limiting и применение правил сигнатур.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        :param config: Словарь с настройками:
            - rate_limit_requests: макс. запросов в окне
            - rate_limit_window: окно rate limit в секундах
            - block_duration: длительность блокировки IP по умолчанию (сек)
            - max_content_length: макс. размер тела запроса (байт)
            - whitelist_ips: список IP для белого списка
        """
        self.config = config or {}
        self.safe_params = set(self.config.get('safe_params', ['csrf_token', '_csrf', 'csrfmiddlewaretoken']))
        self.config = config or {}
        self.rules = WAFSignature.get_all_rules()
        self.ip_blacklist: Set[str] = set()           # постоянно заблокированные IP (например, из админки)
        self.ip_whitelist: Set[str] = set()           # IP, которые никогда не блокируются
        self.request_history: Dict[str, List[datetime]] = defaultdict(list)  # история запросов для rate limit
        self.blocked_ips: Dict[str, Dict] = defaultdict(dict)  # временно заблокированные IP с метаданными

        # Настройки из конфигурации с значениями по умолчанию
        self.rate_limit_requests = int(self.config.get('rate_limit_requests', 100))
        self.rate_limit_window = int(self.config.get('rate_limit_window', 60))
        self.block_duration = int(self.config.get('block_duration', 3600))
        self.max_content_length = int(self.config.get('max_content_length', 10 * 1024 * 1024))

        # Статистика работы
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rules_triggered': defaultdict(int),
            'ip_blocks': 0,
        }

        self._init_whitelist()

    def _init_whitelist(self):
        """Добавляет локальные адреса и IP из конфигурации в белый список."""
        self.ip_whitelist.update(['127.0.0.1', '::1', 'localhost'])
        if 'whitelist_ips' in self.config:
            for ip in self.config['whitelist_ips']:
                self.ip_whitelist.add(ip)

    def is_ip_blacklisted(self, ip: str) -> bool:
        """
        Проверяет, заблокирован ли IP (постоянно или временно).
        Если временная блокировка истекла, удаляет её и возвращает False.
        """
        if ip in self.ip_whitelist:
            return False

        if ip in self.blocked_ips:
            block_info = self.blocked_ips[ip]
            if 'until' in block_info and block_info['until'] > datetime.now(timezone.utc):
                return True
            else:
                # Срок блокировки истёк — удаляем запись
                del self.blocked_ips[ip]
        return False

    def block_ip(self, ip: str, reason: str, duration: Optional[int] = None) -> bool:
        """
        Добавляет IP во временную блокировку.
        :param ip: IP-адрес
        :param reason: причина блокировки (для логов)
        :param duration: длительность блокировки в секундах (если None, используется self.block_duration)
        :return: True, если блокировка успешна; False, если IP в белом списке.
        """
        if ip in self.ip_whitelist:
            logger.warning(f"Попытка блокировки IP из белого списка: {ip}")
            return False

        block_duration = duration or self.block_duration
        block_until = datetime.now(timezone.utc) + timedelta(seconds=block_duration)

        self.blocked_ips[ip] = {
            'blocked_at': datetime.now(timezone.utc),
            'until': block_until,
            'reason': reason,
            'duration': block_duration
        }

        self.stats['ip_blocks'] += 1
        logger.warning(f"IP заблокирован: {ip}, причина: {reason}, до: {block_until}")
        return True

    def check_rate_limit(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Проверяет, не превысил ли IP лимит запросов.
        Возвращает (True, None) если лимит не превышен, иначе (False, сообщение).
        При превышении в два раза от лимита автоматически блокирует IP на 30 минут.
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.rate_limit_window)

        # Оставляем только запросы в текущем окне
        self.request_history[ip] = [
            ts for ts in self.request_history[ip]
            if ts > window_start
        ]

        if len(self.request_history[ip]) >= self.rate_limit_requests:
            oldest_request = min(self.request_history[ip])
            wait_seconds = self.rate_limit_window - (now - oldest_request).total_seconds()

            # Если превышение более чем в 2 раза — блокируем IP (защита от DDoS)
            if len(self.request_history[ip]) >= self.rate_limit_requests * 2:
                self.block_ip(ip, "Превышение rate limit (двойной лимит)", 1800)  # 30 минут

            return False, f"Превышен rate limit. Попробуйте через {wait_seconds:.0f} секунд"

        # Добавляем текущий запрос в историю
        self.request_history[ip].append(now)

        # Ограничиваем размер истории, чтобы избежать бесконечного роста
        if len(self.request_history[ip]) > self.rate_limit_requests * 10:
            self.request_history[ip] = self.request_history[ip][-self.rate_limit_requests:]

        return True, None

    def analyze_request(self, request_data: Dict) -> Dict[str, Any]:
        """
        Главный метод анализа входящего запроса.
        :param request_data: словарь с данными запроса (client_ip, method, url, headers, params, body, path, content_type)
        :return: словарь с результатами:
            - block: bool — требуется ли блокировка
            - findings: список срабатываний правил
            - matched_rules: список ID сработавших правил
            - client_ip: IP клиента
        """
        findings = []
        should_block = False
        matched_rules = []

        ip = request_data.get('client_ip', 'unknown')

        # 1. Проверка чёрного списка
        if self.is_ip_blacklisted(ip):
            return {
                'block': True,
                'reason': 'IP заблокирован',
                'findings': [{'rule_id': 'IP-BLOCKED', 'description': 'IP адрес в черном списке'}]
            }

        # 2. Rate limit
        rate_ok, rate_reason = self.check_rate_limit(ip)
        if not rate_ok:
            return {
                'block': True,
                'reason': rate_reason,
                'findings': [{'rule_id': 'RATE-LIMIT', 'description': 'Превышен rate limit'}]
            }

        # 3. Проверка HTTP метода
        method = request_data.get('method', '').upper()
        if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
            findings.append({
                'rule_id': 'INVALID-METHOD',
                'description': f'Невалидный HTTP метод: {method}',
                'severity': 'medium'
            })

        # 4. Проверка длины URL
        url = request_data.get('url', '')
        if len(url) > 2048:
            findings.append({
                'rule_id': 'LONG-URL',
                'description': f'URL слишком длинный: {len(url)} символов',
                'severity': 'low'
            })

        # 5. Проверка заголовков
        headers = request_data.get('headers', {})
        for header_name, header_value in headers.items():
            if header_name.lower() == 'user-agent':
                if not header_value or len(header_value) < 5:
                    findings.append({
                        'rule_id': 'SUSPICIOUS-UA',
                        'description': 'Подозрительный User-Agent (пустой или слишком короткий)',
                        'severity': 'low'
                    })
            if header_name.lower() == 'referer' and 'javascript:' in header_value.lower():
                findings.append({
                    'rule_id': 'XSS-REFERER',
                    'description': 'XSS в Referer заголовке',
                    'severity': 'high'
                })

        # 6. Проверка параметров запроса (query string)
        params = request_data.get('params', {})
        for param_name, param_value in params.items():
            # Если значение — список (из-за parse_qs), проверяем каждый элемент
            if isinstance(param_value, list):
                for val in param_value:
                    param_findings = self._check_parameter(param_name, val)
                    findings.extend(param_findings)
            else:
                param_findings = self._check_parameter(param_name, param_value)
                findings.extend(param_findings)

        # 7. Проверка тела запроса
        body = request_data.get('body', '')
        if body:
            if len(body) > self.max_content_length:
                findings.append({
                    'rule_id': 'LARGE-BODY',
                    'description': f'Тело запроса слишком большое: {len(body)} байт',
                    'severity': 'medium'
                })
            else:
                body_findings = self._check_request_body(body, request_data.get('content_type', ''))
                findings.extend(body_findings)

        # 8. Проверка пути запроса
        path = request_data.get('path', '')
        path_findings = self._check_path(path)
        findings.extend(path_findings)

        # 9. Определяем, нужно ли блокировать на основе severity
        for finding in findings:
            if finding['severity'] in ['high', 'critical']:
                should_block = True
                matched_rules.append(finding['rule_id'])

        # 10. Обновляем статистику
        self.stats['total_requests'] += 1
        if should_block:
            self.stats['blocked_requests'] += 1
            for rule_id in matched_rules:
                self.stats['rules_triggered'][rule_id] += 1

        return {
            'block': should_block,
            'findings': findings,
            'matched_rules': matched_rules,
            'client_ip': ip
        }

    def _check_parameter(self, param_name: str, param_value: str) -> List[Dict]:
        """Проверить параметр запроса"""
        findings = []

        value_str = str(param_value)

        if param_name.lower() in ['csrf_token', 'csrf-token', '_csrf']:
            return []

        for rule in self.rules:
            if rule.pattern.search(param_name) or rule.pattern.search(value_str):
                findings.append({
                    'rule_id': rule.rule_id,
                    'description': f'{rule.description} в параметре {param_name}',
                    'severity': rule.severity,
                    'value': value_str[:100] if len(value_str) > 100 else value_str
                })
                rule.trigger_count += 1
                rule.last_triggered = datetime.now(timezone.utc)

        return findings

    def _check_request_body(self, body: str, content_type: str) -> List[Dict]:
        findings = []
        parsed = False

        if 'application/json' in content_type:
            try:
                parsed = True
                data = json.loads(body)
                json_findings = self._check_json_structure(data)
                findings.extend(json_findings)
            except json.JSONDecodeError:
                findings.append({
                    'rule_id': 'INVALID-JSON',
                    'description': 'Некорректный JSON в теле запроса',
                    'severity': 'medium'
                })

        elif 'application/x-www-form-urlencoded' in content_type:
            import urllib.parse
            try:
                parsed = True
                parsed_data = urllib.parse.parse_qs(body)
                for key, values in parsed_data.items():
                    if key.lower() in ['csrf_token', 'csrf-token', '_csrf']:
                        continue
                    for value in values:
                        param_findings = self._check_parameter(key, value)
                        findings.extend(param_findings)
            except:
                pass

        if not parsed:
            for rule in self.rules:
                if rule.pattern.search(body):
                    findings.append({
                        'rule_id': rule.rule_id,
                        'description': f'{rule.description} в теле запроса',
                        'severity': rule.severity,
                        'value': body[:100] if len(body) > 100 else body
                    })
                    rule.trigger_count += 1
                    rule.last_triggered = datetime.now(timezone.utc)

        return findings


    def _check_json_structure(self, data: Any, path: str = "") -> List[Dict]:
        """
        Рекурсивно обходит JSON-структуру, проверяя ключи и значения.
        path используется для указания пути к текущему элементу в отчёте.
        """
        findings = []

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                # Проверяем ключ как параметр (он тоже может содержать инъекцию)
                key_findings = self._check_parameter(current_path, key)
                findings.extend(key_findings)

                if isinstance(value, (dict, list)):
                    nested_findings = self._check_json_structure(value, current_path)
                    findings.extend(nested_findings)
                else:
                    value_findings = self._check_parameter(current_path, str(value))
                    findings.extend(value_findings)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    nested_findings = self._check_json_structure(item, current_path)
                    findings.extend(nested_findings)
                else:
                    value_findings = self._check_parameter(current_path, str(item))
                    findings.extend(value_findings)

        return findings

    def _check_path(self, path: str) -> List[Dict]:
        """
        Проверяет путь запроса на наличие признаков атак:
        - directory traversal
        - опасные расширения
        - слишком длинный путь
        - срабатывания сигнатурных правил
        """
        findings = []

        # Проверка на directory traversal (.., ../, ..\)
        if '..' in path or '../' in path or '..\\' in path:
            findings.append({
                'rule_id': 'PATH-TRAVERSAL',
                'description': 'Попытка обхода директорий в пути',
                'severity': 'high',
                'path': path
            })

        # Опасные расширения файлов (могут указывать на попытку доступа к исполняемым файлам)
        dangerous_extensions = ['.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.sh']
        for ext in dangerous_extensions:
            if path.lower().endswith(ext):
                findings.append({
                    'rule_id': 'DANGEROUS-EXTENSION',
                    'description': f'Опасное расширение файла: {ext}',
                    'severity': 'medium',
                    'path': path
                })

        # Проверка длины пути (защита от buffer overflow атак через URL)
        if len(path) > 500:
            findings.append({
                'rule_id': 'LONG-PATH',
                'description': f'Слишком длинный путь: {len(path)} символов',
                'severity': 'low',
                'path': path[:100] + ('...' if len(path) > 100 else '')
            })

        # Применяем все сигнатурные правила к пути
        for rule in self.rules:
            if rule.pattern.search(path):
                findings.append({
                    'rule_id': rule.rule_id,
                    'description': f'{rule.description} в пути запроса',
                    'severity': rule.severity,
                    'path': path
                })
                rule.trigger_count += 1
                rule.last_triggered = datetime.now(timezone.utc)

        return findings

    def get_stats(self) -> Dict:
        """
        Возвращает текущую статистику работы WAF.
        """
        return {
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'block_rate': (self.stats['blocked_requests'] / self.stats['total_requests'] * 100
                           if self.stats['total_requests'] > 0 else 0),
            'rules_triggered': dict(self.stats['rules_triggered']),
            'ip_blocks': self.stats['ip_blocks'],
            'blocked_ips_count': len(self.blocked_ips),
            'active_rules': len([r for r in self.rules if r.trigger_count > 0])
        }

    def clear_old_blocks(self):
        """
        Удаляет из памяти временные блокировки, срок которых истёк.
        Вызывается периодически фоновой задачей.
        """
        now = datetime.now(timezone.utc)
        ips_to_remove = []

        for ip, block_info in self.blocked_ips.items():
            if 'until' in block_info and block_info['until'] < now:
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            del self.blocked_ips[ip]

        if ips_to_remove:
            logger.info(f"Очищено {len(ips_to_remove)} устаревших блокировок IP")


class WAFCaptcha:
    """
    Простая CAPTCHA на основе арифметических примеров.
    Хранит вызовы в памяти с ограниченным временем жизни.
    """

    def __init__(self):
        self.challenges: Dict[str, Dict] = {}   # challenge_id -> данные вызова
        self.challenge_ttl = 300                 # время жизни вызова в секундах

    def generate_challenge(self, client_ip: str) -> Dict:
        """
        Генерирует новый CAPTCHA-вызов для указанного IP.
        Возвращает словарь с challenge_id, вопросом и временем жизни.
        """
        operations = ['+', '-', '*']
        op = random.choice(operations)
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)

        if op == '+':
            answer = num1 + num2
        elif op == '-':
            answer = num1 - num2
        else:
            answer = num1 * num2

        challenge_id = secrets.token_hex(16)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.challenge_ttl)

        self.challenges[challenge_id] = {
            'answer': str(answer),
            'expires_at': expires_at,
            'client_ip': client_ip,
            'question': f"{num1} {op} {num2}"
        }

        return {
            'challenge_id': challenge_id,
            'question': f"Сколько будет {num1} {op} {num2}?",
            'expires_in': self.challenge_ttl
        }

    def verify_challenge(self, challenge_id: str, answer: str) -> bool:
        """
        Проверяет ответ на CAPTCHA.
        Если ответ верен, вызов удаляется и возвращается True.
        Если неверен или истёк срок — возвращается False.
        """
        if challenge_id not in self.challenges:
            return False

        challenge = self.challenges[challenge_id]

        if challenge['expires_at'] < datetime.now(timezone.utc):
            del self.challenges[challenge_id]
            return False

        is_valid = str(answer).strip() == challenge['answer']
        del self.challenges[challenge_id]   # одноразовый вызов
        return is_valid

    def cleanup_expired(self):
        """Удаляет все просроченные вызовы."""
        now = datetime.now(timezone.utc)
        expired = [cid for cid, ch in self.challenges.items()
                   if ch['expires_at'] < now]

        for cid in expired:
            del self.challenges[cid]


class WAFMiddleware:
    """
    ASGI-совместимый middleware для интеграции WAF в FastAPI/Starlette.
    Перехватывает HTTP-запросы, анализирует их через WAFEngine,
    при необходимости блокирует или запрашивает CAPTCHA.
    """

    def __init__(self, app, waf_config: Optional[Dict] = None):
        """
        :param app: ASGI-приложение (обычно FastAPI)
        :param waf_config: конфигурация для WAFEngine
        """
        self.app = app
        self.waf = WAFEngine(waf_config)
        self.captcha = WAFCaptcha()

        # Пути, которые не должны проверяться WAF
        self.excluded_paths = [
            '/static/',
            '/health',
            '/favicon.ico',
            '/robots.txt',
            '/waf/stats',
            '/waf/captcha'
        ]

        self._start_cleanup_task()

    async def __call__(self, scope, receive, send):
        """ASGI entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Собираем информацию о запросе
        request = self._create_request_object(scope)

        # Пропускаем исключённые пути
        if self._should_exclude_path(request['path']):
            await self.app(scope, receive, send)
            return

        # Анализируем запрос через движок WAF
        analysis = self.waf.analyze_request(request)

        # Если нужно заблокировать
        if analysis['block']:
            response = self._create_blocked_response(analysis, request)
            await self._send_response(scope, send, response)
            return

        # Обработка CAPTCHA (если клиент прислал заголовки)
        # (заглушка — в реальном проекте логика может быть сложнее)
        if 'x-captcha-id' in request.get('headers', {}) and 'x-captcha-answer' in request.get('headers', {}):
            captcha_id = request['headers']['x-captcha-id']
            captcha_answer = request['headers']['x-captcha-answer']
            if not self.captcha.verify_challenge(captcha_id, captcha_answer):
                response = self._create_captcha_required_response()
                await self._send_response(scope, send, response)
                return

        # Пропускаем запрос дальше по цепочке
        await self.app(scope, receive, send)

    def _create_request_object(self, scope) -> Dict:
        """
        Преобразует ASGI scope в словарь с данными, необходимыми для анализа.
        """
        from urllib.parse import parse_qs, urlparse

        client_ip = self._get_client_ip(scope)
        method = scope.get('method', 'GET')
        raw_path = scope.get('raw_path', b'/').decode()
        parsed_url = urlparse(raw_path)
        path = parsed_url.path

        headers = {}
        for key, value in scope.get('headers', []):
            headers[key.decode().lower()] = value.decode()

        query_string = parsed_url.query
        params = parse_qs(query_string)

        request = {
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'url': raw_path,
            'headers': headers,
            'params': params,
            'content_type': headers.get('content-type', ''),
        }

        # Для методов, которые могут содержать тело, добавляем пустую строку (тело будет прочитано позже)
        if method in ['POST', 'PUT', 'PATCH']:
            request['body'] = ''

        return request

    def _get_client_ip(self, scope) -> str:
        """
        Извлекает реальный IP клиента из заголовков X-Forwarded-For и подобных.
        """
        client = scope.get('client')
        if client:
            return client[0]

        headers = dict(
            (k.decode().lower(), v.decode())
            for k, v in scope.get('headers', [])
        )

        for header in ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']:
            if header in headers:
                ip = headers[header].split(',')[0].strip()
                if self._is_valid_ip(ip):
                    return ip

        return 'unknown'

    def _is_valid_ip(self, ip: str) -> bool:
        """Проверяет, является ли строка валидным IP-адресом."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _should_exclude_path(self, path: str) -> bool:
        """Определяет, нужно ли пропустить проверку WAF для данного пути."""
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                return True
        return False

    def _create_blocked_response(self, analysis: Dict, request: Dict) -> Dict:
        """
        Формирует HTTP-ответ для заблокированного запроса.
        Включает информацию о нарушениях.
        """
        findings = analysis.get('findings', [])
        critical_findings = [f for f in findings if f.get('severity') in ['high', 'critical']]

        response = {
            'status': 403,
            'headers': [
                (b'content-type', b'application/json'),
                (b'x-waf-blocked', b'true'),
                (b'x-waf-reason', b'security_violation'),
            ],
            'body': json.dumps({
                'error': 'Запрос заблокирован WAF',
                'request_id': secrets.token_hex(8),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'client_ip': request.get('client_ip', 'unknown'),
                'violations': [
                    {
                        'rule_id': f.get('rule_id'),
                        'description': f.get('description'),
                        'severity': f.get('severity')
                    }
                    for f in critical_findings[:3]   # ограничим тремя для краткости
                ],
                'message': 'Ваш запрос содержит признаки атаки и был заблокирован.',
                'support_contact': 'artifex.dnevnik@gmail.com'
            }, ensure_ascii=False).encode('utf-8')
        }

        logger.warning(
            f"WAF заблокировал запрос от {request.get('client_ip')}: "
            f"{request.get('method')} {request.get('path')} - "
            f"Нарушения: {[f['rule_id'] for f in critical_findings]}"
        )

        return response

    def _create_captcha_required_response(self) -> Dict:
        """Формирует ответ с требованием пройти CAPTCHA."""
        response = {
            'status': 429,
            'headers': [
                (b'content-type', b'application/json'),
                (b'x-waf-captcha-required', b'true'),
            ],
            'body': json.dumps({
                'error': 'Требуется подтверждение CAPTCHA',
                'message': 'Пожалуйста, решите CAPTCHA для продолжения',
                'captcha_required': True,
                'retry_after': 30
            }, ensure_ascii=False).encode('utf-8')
        }
        return response

    async def _send_response(self, scope, send, response: Dict):
        """Отправляет сформированный HTTP-ответ."""
        await send({
            'type': 'http.response.start',
            'status': response['status'],
            'headers': response['headers']
        })

        await send({
            'type': 'http.response.body',
            'body': response['body']
        })

    def _start_cleanup_task(self):
        """
        Запускает фоновую задачу для очистки устаревших блокировок и CAPTCHA.
        """
        async def cleanup_worker():
            while True:
                try:
                    self.waf.clear_old_blocks()
                    self.captcha.cleanup_expired()
                    await asyncio.sleep(300)  # каждые 5 минут
                except Exception as e:
                    logger.error(f"Ошибка в cleanup worker: {e}")
                    await asyncio.sleep(60)

        loop = asyncio.get_event_loop()
        loop.create_task(cleanup_worker())

    def get_waf_stats(self) -> Dict:
        """Возвращает статистику WAF."""
        return self.waf.get_stats()


class WAFManager:
    """
    Менеджер для управления WAF через API.
    Предоставляет методы для блокировки/разблокировки IP, работы с белым списком.
    """

    def __init__(self, waf_engine: WAFEngine):
        self.waf = waf_engine

    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> Dict:
        """Блокирует IP через API."""
        success = self.waf.block_ip(ip, reason, duration)
        return {
            'success': success,
            'ip': ip,
            'reason': reason,
            'duration': duration
        }

    def unblock_ip(self, ip: str) -> Dict:
        """Снимает временную блокировку с IP."""
        if ip in self.waf.blocked_ips:
            del self.waf.blocked_ips[ip]
            return {'success': True, 'ip': ip, 'message': 'IP разблокирован'}
        return {'success': False, 'ip': ip, 'message': 'IP не найден в черном списке'}

    def get_blocked_ips(self) -> List[Dict]:
        """Возвращает список временно заблокированных IP с метаданными."""
        result = []
        for ip, info in self.waf.blocked_ips.items():
            result.append({
                'ip': ip,
                'blocked_at': info.get('blocked_at').isoformat() if info.get('blocked_at') else None,
                'blocked_until': info.get('until').isoformat() if info.get('until') else None,
                'reason': info.get('reason', 'unknown'),
                'duration': info.get('duration', 0)
            })
        return result

    def add_whitelist_ip(self, ip: str) -> Dict:
        """Добавляет IP в белый список (постоянно)."""
        if self._is_valid_ip(ip):
            self.waf.ip_whitelist.add(ip)
            return {'success': True, 'ip': ip, 'message': 'IP добавлен в белый список'}
        return {'success': False, 'ip': ip, 'message': 'Неверный формат IP'}

    def remove_whitelist_ip(self, ip: str) -> Dict:
        """Удаляет IP из белого списка."""
        if ip in self.waf.ip_whitelist:
            self.waf.ip_whitelist.remove(ip)
            return {'success': True, 'ip': ip, 'message': 'IP удален из белого списка'}
        return {'success': False, 'ip': ip, 'message': 'IP не найден в белом списке'}

    def get_whitelist(self) -> List[str]:
        """Возвращает список IP в белом списке."""
        return list(self.waf.ip_whitelist)

    def _is_valid_ip(self, ip: str) -> bool:
        """Проверяет корректность IP-адреса."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


# -------------------------------------------------------------------
# FastAPI роуты для управления WAF
# -------------------------------------------------------------------
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse

waf_router = APIRouter(prefix="/waf", tags=["WAF"])

# Глобальные инстансы (для простоты примера; в реальном проекте лучше использовать dependency injection)
waf_instance = None
waf_manager = None

def get_waf():
    """Dependency для получения инстанса WAFEngine."""
    global waf_instance, waf_manager
    if waf_instance is None:
        waf_instance = WAFEngine({
            'rate_limit_requests': 100,
            'rate_limit_window': 60,
            'block_duration': 3600,
            'max_content_length': 10 * 1024 * 1024,
        })
        waf_manager = WAFManager(waf_instance)
    return waf_instance

def get_waf_manager():
    """Dependency для получения менеджера WAF."""
    global waf_manager
    if waf_manager is None:
        get_waf()
    return waf_manager


@waf_router.get("/stats")
async def get_waf_stats(waf: WAFEngine = Depends(get_waf)):
    """Возвращает статистику работы WAF."""
    stats = waf.get_stats()
    return JSONResponse(stats)


@waf_router.get("/rules")
async def get_waf_rules():
    """Возвращает список всех правил WAF с их текущими счётчиками."""
    rules = []
    for rule in WAFSignature.get_all_rules():
        rules.append({
            'id': rule.rule_id,
            'description': rule.description,
            'severity': rule.severity,
            'action': rule.action,
            'trigger_count': rule.trigger_count,
            'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None
        })
    return JSONResponse({'rules': rules, 'total': len(rules)})


@waf_router.get("/blocked-ips")
async def get_blocked_ips(manager: WAFManager = Depends(get_waf_manager)):
    """Возвращает список временно заблокированных IP."""
    ips = manager.get_blocked_ips()
    return JSONResponse({'blocked_ips': ips, 'count': len(ips)})


@waf_router.post("/block-ip")
async def block_ip(
        ip: str,
        reason: str = "Manual block",
        duration: int = 3600,
        manager: WAFManager = Depends(get_waf_manager)
):
    """Блокирует указанный IP адрес."""
    result = manager.block_ip(ip, reason, duration)
    return JSONResponse(result)


@waf_router.post("/unblock-ip")
async def unblock_ip(ip: str, manager: WAFManager = Depends(get_waf_manager)):
    """Снимает блокировку с IP."""
    result = manager.unblock_ip(ip)
    return JSONResponse(result)


@waf_router.get("/whitelist")
async def get_whitelist(manager: WAFManager = Depends(get_waf_manager)):
    """Возвращает белый список IP."""
    whitelist = manager.get_whitelist()
    return JSONResponse({'whitelist': whitelist, 'count': len(whitelist)})


@waf_router.post("/whitelist/add")
async def add_to_whitelist(ip: str, manager: WAFManager = Depends(get_waf_manager)):
    """Добавляет IP в белый список."""
    result = manager.add_whitelist_ip(ip)
    return JSONResponse(result)


@waf_router.delete("/whitelist/remove")
async def remove_from_whitelist(ip: str, manager: WAFManager = Depends(get_waf_manager)):
    """Удаляет IP из белого списка."""
    result = manager.remove_whitelist_ip(ip)
    return JSONResponse(result)


@waf_router.post("/captcha/generate")
async def generate_captcha(request: Request):
    """Генерирует новый CAPTCHA-вызов для клиента."""
    client_ip = request.client.host if request.client else 'unknown'
    captcha = WAFCaptcha()
    challenge = captcha.generate_challenge(client_ip)
    return JSONResponse({
        'success': True,
        'challenge': challenge,
        'message': 'Решите задачу и отправьте ответ в заголовке X-Captcha-Answer'
    })


@waf_router.get("/test")
async def test_waf(request: Request):
    """Тестовый эндпоинт для проверки доступности WAF."""
    return JSONResponse({
        'status': 'ok',
        'message': 'WAF работает',
        'client_ip': request.client.host if request.client else 'unknown',
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# -------------------------------------------------------------------
# Middleware для анализа тела запроса (отдельно от ASGI middleware)
# -------------------------------------------------------------------
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response
import io


class WAFRequestBodyMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware для анализа тела POST-запросов.
    Читает тело, передаёт его в WAFEngine и при необходимости блокирует запрос.
    """

    def __init__(self, app, waf_engine: WAFEngine):
        super().__init__(app)
        self.waf = waf_engine

    async def dispatch(self, request: StarletteRequest, call_next):
        client_ip = request.client.host if request.client else 'unknown'

        # Проверка чёрного списка и rate limit уже выполнены в WAFMiddleware,
        # но дублируем для надёжности (можно убрать, если уверены)
        if self.waf.is_ip_blacklisted(client_ip):
            return JSONResponse(
                status_code=403,
                content={
                    'error': 'Доступ запрещен',
                    'message': 'Ваш IP адрес заблокирован',
                    'request_id': secrets.token_hex(8)
                }
            )

        rate_ok, rate_reason = self.waf.check_rate_limit(client_ip)
        if not rate_ok:
            return JSONResponse(
                status_code=429,
                content={
                    'error': 'Слишком много запросов',
                    'message': rate_reason,
                    'retry_after': 60
                },
                headers={'Retry-After': '60'}
            )

        request_data = {
            'client_ip': client_ip,
            'method': request.method,
            'path': request.url.path,
            'url': str(request.url),
            'headers': dict(request.headers),
            'params': dict(request.query_params),
            'content_type': request.headers.get('content-type', ''),
        }

        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                # Читаем тело запроса
                body_bytes = await request.body()
                request_data['body'] = body_bytes.decode('utf-8', errors='ignore')

                # Анализируем
                analysis = self.waf.analyze_request(request_data)

                if analysis['block']:
                    return self._create_blocked_response(analysis, request_data)

                # Восстанавливаем тело для последующих middleware/обработчиков
                request._body = body_bytes

                # Подменяем receive, чтобы следующие обработчики могли прочитать тело
                async def receive_body():
                    return {
                        'type': 'http.request',
                        'body': body_bytes,
                        'more_body': False
                    }

                original_receive = request.receive

                async def new_receive():
                    if not hasattr(request, '_body_read'):
                        request._body_read = True
                        return await receive_body()
                    return await original_receive()

                request.receive = new_receive

            except Exception as e:
                logger.error(f"Ошибка анализа тела запроса: {e}")

        response = await call_next(request)

        # Добавляем заголовки, информирующие о защите WAF
        response.headers['X-WAF-Protected'] = 'true'
        response.headers['X-WAF-Request-ID'] = secrets.token_hex(8)

        return response

    def _create_blocked_response(self, analysis: Dict, request_data: Dict) -> Response:
        findings = analysis.get('findings', [])
        critical_findings = [f for f in findings if f.get('severity') in ['high', 'critical']]

        response_data = {
            'error': 'Запрос заблокирован системой безопасности',
            'request_id': secrets.token_hex(8),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'client_ip': request_data.get('client_ip', 'unknown'),
            'violations': [
                {
                    'rule_id': f.get('rule_id'),
                    'description': f.get('description'),
                    'severity': f.get('severity')
                }
                for f in critical_findings[:3]
            ],
            'message': 'Ваш запрос содержит признаки атаки и был заблокирован.',
            'support_contact': 'artifex.dnevnik@gmail.com'
        }

        logger.warning(
            f"WAF заблокировал запрос от {request_data.get('client_ip')}: "
            f"{request_data.get('method')} {request_data.get('path')} - "
            f"Нарушения: {[f['rule_id'] for f in critical_findings]}"
        )

        return JSONResponse(
            status_code=403,
            content=response_data,
            headers={
                'X-WAF-Blocked': 'true',
                'X-WAF-Reason': 'security_violation'
            }
        )


# -------------------------------------------------------------------
# Функция установки WAF в FastAPI приложение
# -------------------------------------------------------------------
def setup_waf(app, config: Optional[Dict] = None) -> WAFEngine:
    """
    Инициализирует WAF и подключает middleware и роуты к FastAPI приложению.
    Возвращает экземпляр WAFEngine для дальнейшего использования.
    """
    waf_engine = WAFEngine(config)

    # Добавляем middleware для анализа тела запроса
    app.add_middleware(WAFRequestBodyMiddleware, waf_engine=waf_engine)

    # Добавляем роуты управления WAF
    app.include_router(waf_router)

    # Обработчик исключений для 403 (можно расширить)
    @app.exception_handler(HTTPException)
    async def waf_exception_handler(request: Request, exc: HTTPException):
        if exc.status_code == 403:
            return JSONResponse(
                status_code=403,
                content={
                    'error': 'Доступ запрещен',
                    'message': exc.detail,
                    'request_id': secrets.token_hex(8)
                },
                headers={'X-WAF-Protected': 'true'}
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={'error': exc.detail}
        )

    logger.info("WAF успешно инициализирован")
    return waf_engine


# Конфигурация по умолчанию
DEFAULT_WAF_CONFIG = {
    'rate_limit_requests': 100,
    'rate_limit_window': 60,
    'block_duration': 3600,
    'max_content_length': 10 * 1024 * 1024,
    'whitelist_ips': [],
    'enable_captcha': True,
    'log_level': 'INFO',
}