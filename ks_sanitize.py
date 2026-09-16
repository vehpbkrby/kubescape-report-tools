#!/usr/bin/env python3
"""Безопасная выжимка из JSON-отчёта kubescape.

В выжимку по белому списку попадают только сводка по проверкам и находки:
ресурс (тип, namespace, имя), номер проверки, статус и пути к полям.
Раздел resources с полными копиями объектов кластера не копируется вовсе.

Потом выжимка проверяется автоматически:
  1. ни одно значение оригинала, похожее на секрет (переменные окружения и
     аргументы с именами вроде password, данные Secret, пары «password: …»
     внутри значений, случайные строки вроде токенов), в выжимке не
     встречается; совпадения замазываются;
  2. строки, похожие на ключи, токены и пароли, тоже замазываются;
  3. логины пользователей и адреса почты заменены псевдонимами.

Значения секретов скрипт не печатает никогда, только места, где они лежат.

Запуск:  python ks_sanitize.py results.json
Рядом с отчётом появятся:
  results.sanitized.json      выжимка, её можно передавать для разбора;
  results.secret-places.csv   где в оригинале лежат секреты, без значений;
  results.users.csv           псевдоним -> настоящее имя, остаётся у вас.
"""

import base64
import binascii
import csv
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

MIN_LEN = 6   # более короткие значения не сверяем: слишком много случайных совпадений
SHOW = 30     # сколько мест каждого вида печатать

# имена переменных, ключей и флагов, под которыми обычно лежат секреты
SUSPICIOUS = re.compile(
    r"passw|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|dsn", re.I)
# ссылки на секрет, а не сам секрет: SECRET_NAME, passwordFile, tokenPath
REFERENCE = re.compile(r"(name|ref|file|path|namespace|selector)$", re.I)
# флаги включения функций: --enable-bootstrap-token-auth, enable-policy-secrets-sync
FEATURE_FLAG = re.compile(r"-*(enable|disable)", re.I)
# ключи ConfigMap, которые на деле имена файлов: миграции, запросы, конфиги
FILE_NAME = re.compile(
    r"\.(sql|gql|graphql|ya?ml|json|conf|cfg|ini|properties|toml|xml|txt|sh|js|py|lua|tpl|env)$", re.I)
NOT_SECRET = {"true", "false", "yes", "no", "on", "off", "enabled", "disabled", "none", "null", "0", "1"}
# типы GraphQL и SQL, которые регулярка «password: …» принимает за значения
TYPE_WORDS = {"string", "int", "integer", "bigint", "uuid", "text", "varchar", "boolean", "bool",
              "timestamp", "timestamptz", "jsonb"}
# служебные аннотации без секретов: трекинг Argo CD, метаданные Helm, контрольные суммы
META_ANNOTATIONS = ("argocd.argoproj.io/", "meta.helm.sh/", "deployment.kubernetes.io/", "checksum/")
# так kubescape прячет значения переменных окружения; форма записи (value, а не secretKeyRef) остаётся
MASKED = re.compile(r"^(?:[xX]{4,}|\*{4,})$")
ENV_MASKED = "переменные-секреты, значение скрыто сканером"
# «password: значение» внутри конфигов и JSON
KV = re.compile(
    r"""([\w.-]*(?:passw|pwd|secret|token|api[_-]?key|credential)[\w.-]*)["']?\s*[:=]\s*["']?([^\s"'#,;(){}\[\]]+)""",
    re.I)
URL_CREDS = re.compile(r"://([^/\s:@\"']+):([^/\s@\"']+)@")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
LEAK_PATTERNS = {
    "закрытый ключ": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY"),
    "JWT-токен": re.compile(r"eyJ[\w-]{10,}\.[\w-]{10,}"),
    "ключ AWS": re.compile(r"AKIA[0-9A-Z]{16}"),
    "логин и пароль в адресе": URL_CREDS,
    "присваивание пароля или токена": re.compile(
        r"(?:passw\w*|pwd|secret|token)\s*[:=]\s*\S{4,}", re.I),
    "длинная base64-строка": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
}
CONTAINER_KEYS = ("containers", "initContainers", "ephemeralContainers")
DATA_KEYS = ("data", "stringData", "binaryData")
SKIP_KEYS = ("labels", "matchLabels", "selector", "nodeSelector")  # метки — имена, не секреты
SUBJECT_KINDS = ("User", "Group", "ServiceAccount")
# сервисные аккаунты и группы, названные по людям: a.ivanov-devops, ivanov.a
PERSON = re.compile(r"^(?:[a-z]{1,2}\.[a-z][a-z-]{2,}|[a-z]{3,}\.[a-z]{1,2})(?:[-_.][\w.-]*)?$", re.I)
REDACTED = "[скрыто]"


def random_like(value):
    """Похоже на сгенерированный токен или ключ: длинное, без пробелов, пёстрое."""
    if not 16 <= len(value) <= 512 or value.startswith(("-", "/")):
        return False
    if any(ch.isspace() for ch in value):
        return False
    if not (any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)):
        return False
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values()) >= 3.5


def looks_secret(name, value):
    return (bool(SUSPICIOUS.search(name)) and not REFERENCE.search(name)
            and not FEATURE_FLAG.match(name)
            and isinstance(value, str) and bool(value) and value.lower() not in NOT_SECRET
            and not value.startswith(("/", "$(")))


class Collector:
    """Значения оригинала, похожие на секреты, и счётчики."""

    def __init__(self):
        self.values = {}          # значение -> где лежит в оригинале
        self.kinds = Counter()
        self.stats = Counter()
        self.flagged = {}         # вид -> места, без значений
        self.kv_values = set()
        self.url_passwords = set()
        self.quiet = False        # внутри last-applied: сверяем, но не считаем

    def add(self, value, where, candidate=False, b64=False):
        """Запоминает значение для сверки, если оно может быть секретом."""
        if not isinstance(value, str) or not value:
            return
        found = [value]
        if "=" in value:
            found.append(value.split("=", 1)[1])
        inner = []
        for m in KV.finditer(value):
            key, v = m.group(1).strip("-."), m.group(2)
            if (len(v) >= 4 and v[0] not in "{$<" and not v.endswith("!")
                    and v.lower() not in NOT_SECRET | TYPE_WORDS
                    and not REFERENCE.search(key) and not FEATURE_FLAG.match(key)):
                inner.append(v)
                self.kv_values.add(v)
        for m in URL_CREDS.finditer(value):
            inner.append(m.group(2))
            self.url_passwords.add(m.group(2))
        if inner:
            self.flag("пароли внутри значений", f"{where} ({len(inner)})")
        for v in found:
            if len(v) >= MIN_LEN and (candidate or random_like(v)):
                self.values.setdefault(v, where)
        for v in inner:
            if len(v) >= MIN_LEN:
                self.values.setdefault(v, where)
        if b64:
            try:
                decoded = base64.b64decode(value, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return
            self.add(decoded, where + " (base64)", candidate=True)

    def count(self, key):
        if not self.quiet:
            self.stats[key] += 1

    def flag(self, kind, where):
        if not self.quiet:
            self.flagged.setdefault(kind, {})[where] = None


def label_of(obj):
    meta = obj.get("metadata") or {}
    name = meta.get("name") or obj.get("name") or "?"
    return f"{obj.get('kind') or '?'} {meta.get('namespace') or '-'}/{name}"


def scan_resource(obj, col, label=None):
    kind = obj.get("kind") or "?"
    label = label or label_of(obj)
    if not col.quiet:
        col.kinds[kind] += 1
    if kind in ("ConfigMap", "Secret"):
        if kind == "Secret":
            col.count("secrets")
        for field in DATA_KEYS:
            data = obj.get(field)
            if not isinstance(data, dict):
                continue
            for key, value in data.items():
                named = looks_secret(key, value) and not FILE_NAME.search(key)
                b64 = (kind == "Secret" and field == "data") or field == "binaryData"
                col.add(value, f"{label} · {field}.{key}", candidate=kind == "Secret" or named, b64=b64)
                if kind == "ConfigMap" and named:
                    col.flag("ключи ConfigMap", f"{label} · {key}")
        obj = {k: v for k, v in obj.items() if k not in DATA_KEYS}
    walk(obj, "", label, col)


def walk(node, path, label, col):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in SKIP_KEYS:
                continue
            p = f"{path}.{key}" if path else key
            if key in CONTAINER_KEYS and isinstance(value, list):
                for c in value:
                    if isinstance(c, dict):
                        scan_container(c, label, col)
            elif key == "annotations" and isinstance(value, dict):
                scan_annotations(value, p, label, col)
                continue
            elif isinstance(value, str) and SUSPICIOUS.search(key):
                named = looks_secret(key, value)
                col.add(value, f"{label} · {p}", candidate=named)
                if named and len(value) >= MIN_LEN:
                    col.flag("поля объектов", f"{label} · {p}")
            walk(value, p, label, col)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            walk(value, f"{path}[{i}]", label, col)


def scan_container(c, label, col):
    cname = c.get("name") or "?"
    for e in c.get("env") or []:
        if not isinstance(e, dict) or not isinstance(e.get("value"), str):
            continue
        name = e.get("name") or "?"
        col.count("env_literal")
        if MASKED.match(e["value"]):
            col.count("env_masked")
            if SUSPICIOUS.search(name) and not REFERENCE.search(name) and not FEATURE_FLAG.match(name):
                col.flag(ENV_MASKED, f"{label} · {cname} · {name}")
            continue
        named = looks_secret(name, e["value"])
        col.add(e["value"], f"{label} · {cname} · env {name}", candidate=named)
        if named:
            col.flag("переменные окружения", f"{label} · {cname} · {name}")
    for key in ("command", "args"):
        prev = ""
        for i, arg in enumerate(c.get(key) or []):
            if not isinstance(arg, str):
                prev = ""
                continue
            if "=" in arg or not prev:
                flag, _, value = arg.partition("=")
            else:  # «--password значение» двумя аргументами
                flag, value = prev, arg
            named = looks_secret(flag, value)
            col.add(arg, f"{label} · {cname} · {key}[{i}]", candidate=named)
            if named:
                col.flag("аргументы запуска", f"{label} · {cname} · {flag}")
            prev = arg if arg.startswith("-") and "=" not in arg else ""


def scan_annotations(annotations, path, label, col):
    for key, value in annotations.items():
        if key.startswith(META_ANNOTATIONS):
            continue
        col.add(value, f"{label} · {path}.{key}")
        if not key.endswith("last-applied-configuration"):
            continue
        col.count("last_applied")
        # в копии манифеста могут остаться старые значения, которых уже нет в объекте
        try:
            applied = json.loads(value)
        except (TypeError, ValueError):
            continue
        if isinstance(applied, dict):
            quiet, col.quiet = col.quiet, True
            scan_resource(applied, col, label=f"{label} · last-applied")
            col.quiet = quiet


class Pseudonyms:
    def __init__(self):
        self.names = {}
        self.counts = Counter()

    def get(self, original, prefix):
        if original not in self.names:
            self.counts[prefix] += 1
            self.names[original] = f"{prefix}-{self.counts[prefix]:02d}"
        return self.names[original]


def parse_resource_id(rid):
    """Тип, namespace и имя ресурса из resourceID kubescape.

    Обычный ресурс: группа/версия/namespace/тип/имя (без namespace третья часть пустая).
    Субъект RBAC: группа/namespace/тип/имя, за ним роль и привязка в обычном виде.
    """
    parts = rid.split("/")
    if len(parts) > 5 and parts[2] in SUBJECT_KINDS and (len(parts) - 4) % 5 == 0:
        item = {"kind": parts[2], "namespace": parts[1], "name": parts[3]}
        for i in range(4, len(parts), 5):
            _, _, ns, kind, name = parts[i:i + 5]
            item["binding" if kind.endswith("Binding") else "role"] = \
                f"{kind} {ns}/{name}" if ns else f"{kind} {name}"
            if not item["namespace"] and item["kind"] == "ServiceAccount":
                item["namespace"] = ns
        return item
    parts = rid.split("/", 4)
    if len(parts) == 5:
        return {"kind": parts[3], "namespace": parts[2], "name": parts[4]}
    return {"kind": "", "namespace": "", "name": rid}


def is_builtin_user(name):
    return name.startswith("system:") or name in ("kubernetes-admin", "admin")


def is_person(kind, name):
    if kind == "User":
        return not is_builtin_user(name)
    return kind in ("ServiceAccount", "Group") and bool(PERSON.match(name))


def as_text(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def status_of(item):
    status = item.get("status")
    if isinstance(status, dict):
        return status.get("status", ""), status.get("subStatus", "")
    return status or "", item.get("subStatus", "")


def severity(score_factor):
    if not isinstance(score_factor, (int, float)):
        return ""
    if score_factor < 4:
        return "Low"
    if score_factor < 7:
        return "Medium"
    return "High" if score_factor < 9 else "Critical"


def control_summary(cid, c):
    counters = c.get("ResourceCounters") or {}
    category = c.get("category") or {}
    item = {
        "id": c.get("controlID") or cid,
        "name": c.get("name", ""),
        "status": c.get("status", ""),
        "severity": c.get("severity") or severity(c.get("scoreFactor")),
        "scoreFactor": c.get("scoreFactor"),
        "complianceScore": round(c.get("complianceScore") or 0, 1),
        "failed": counters.get("failedResources", 0),
        "passed": counters.get("passedResources", 0),
        "skipped": counters.get("skippedResources", 0),
        "excluded": counters.get("excludedResources", 0),
        "ignored": (c.get("subStatusCounters") or {}).get("ignoredResources", 0),
        "category": category.get("name", ""),
        "subcategory": (category.get("subCategory") or {}).get("name", ""),
    }
    if item["status"] == "skipped":
        item["skipReason"] = (c.get("statusInfo") or {}).get("info", "")
    return item


def rule_details(rules):
    paths = {"failed": [], "fix": [], "review": [], "delete": []}
    commands, exceptions = [], []

    def fix(fp):
        if isinstance(fp, dict) and fp.get("path"):
            paths["fix"].append({"path": fp["path"], "value": as_text(fp.get("value", ""))})

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for p in rule.get("paths") or []:
            if not isinstance(p, dict):
                continue
            for key, bucket in (("failedPath", "failed"), ("reviewPath", "review"),
                                ("deletePath", "delete")):
                if isinstance(p.get(key), str) and p[key]:
                    paths[bucket].append(p[key])
            fix(p.get("fixPath"))
            if isinstance(p.get("fixCommand"), str) and p["fixCommand"]:
                commands.append(p["fixCommand"])
        # старый формат отчёта
        paths["failed"] += [x for x in rule.get("failedPaths") or [] if isinstance(x, str)]
        for fp in rule.get("fixPaths") or []:
            fix(fp)
        if isinstance(rule.get("fixCommand"), str) and rule["fixCommand"]:
            commands.append(rule["fixCommand"])
        for ex in rule.get("exceptions") or []:
            if isinstance(ex, dict) and ex.get("name"):
                exceptions.append(ex["name"])
    return {k: v for k, v in paths.items() if v}, commands, exceptions


def build_findings(results, pseudo):
    findings = []
    for res in results:
        if not isinstance(res, dict):
            continue
        ident = parse_resource_id(res.get("resourceID") or "")
        if is_person(ident["kind"], ident["name"]):
            ident["name"] = pseudo.get(ident["name"], "user")
        for ctl in res.get("controls") or []:
            status, sub = status_of(ctl)
            if status == "passed" and not sub:
                continue
            paths, commands, exceptions = rule_details(ctl.get("rules") or [])
            item = {"control": ctl.get("controlID", ""), "status": status, **ident}
            if sub:
                item["subStatus"] = sub
            if paths:
                item["paths"] = paths
            if commands:
                item["fixCommands"] = commands
            if exceptions:
                item["exceptions"] = sorted(set(exceptions))
            findings.append(item)
    return findings


def leaves(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from leaves(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from leaves(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def map_strings(node, fn):
    if isinstance(node, dict):
        return {k: map_strings(v, fn) for k, v in node.items()}
    if isinstance(node, list):
        return [map_strings(v, fn) for v in node]
    return fn(node) if isinstance(node, str) else node


def mb(path):
    return f"{path.stat().st_size / 1024 / 1024:.1f} МБ"


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 2:
        sys.exit("Запуск: python ks_sanitize.py <JSON-отчёт kubescape>")
    src = Path(sys.argv[1])
    report = json.loads(src.read_text(encoding="utf-8-sig"))
    if not isinstance(report, dict) or "summaryDetails" not in report:
        sys.exit("Это не похоже на JSON-отчёт kubescape: нет раздела summaryDetails.")

    # 1. что лежит в копиях объектов; сами значения идут только в сверку
    col = Collector()
    pseudo = Pseudonyms()
    identity = set()
    for item in report.get("resources") or []:
        obj = item.get("object", item) if isinstance(item, dict) else None
        if not isinstance(obj, dict):
            continue
        meta = obj.get("metadata") or {}
        identity.update(x for x in (meta.get("name"), meta.get("namespace"), obj.get("name"))
                        if isinstance(x, str))
        subject = obj.get("name") or meta.get("name")
        if isinstance(subject, str) and is_person(obj.get("kind"), subject):
            pseudo.get(subject, "user")
        scan_resource(obj, col)

    # 2. выжимка по белому списку
    results = report.get("results") or []
    for res in results:
        if isinstance(res, dict):
            identity.update((res.get("resourceID") or "").split("/"))
    identity.discard("")
    sd = report["summaryDetails"]
    out = {
        "source": "kubescape",
        "generationTime": report.get("generationTime", ""),
        "kubernetes": (report.get("clusterAPIServerInfo") or {}).get("gitVersion", ""),
        "complianceScore": round(sd.get("complianceScore") or 0, 1),
        "frameworks": [
            {"name": f.get("name", ""), "version": f.get("version", ""),
             "complianceScore": round(f.get("complianceScore") or 0, 1)}
            for f in sd.get("frameworks") or [] if isinstance(f, dict)
        ],
        "controls": sorted((control_summary(cid, c) for cid, c in (sd.get("controls") or {}).items()
                            if isinstance(c, dict)), key=lambda c: c["id"]),
        "findings": build_findings(results, pseudo),
    }
    # логин встречается и в именах привязок ролей, поэтому заменяется везде
    logins = sorted((n for n in pseudo.names if len(n) >= 4), key=len, reverse=True)

    def hide_people(s):
        for login in logins:
            if login in s:
                s = s.replace(login, pseudo.names[login])
        return EMAIL.sub(lambda m: pseudo.get(m.group(0), "email"), s)
    out = map_strings(out, hide_people)

    # 3. сверка: секреты оригинала не должны встречаться в выжимке;
    #    части имён ресурсов (имя узла внутри имени пода) секретами не считаются
    blob = "\n".join({s for _, s in leaves(out)})
    ident_blob = "\n".join(identity)
    hits = {v: where for v, where in col.values.items() if v in blob and v not in ident_blob}
    hit_places = {}
    if hits:
        for path, s in leaves(out):
            for v in hits:
                if v in s:
                    hit_places.setdefault(hits[v], []).append(path)
        ordered = sorted(hits, key=len, reverse=True)

        def scrub(s):
            for v in ordered:
                s = s.replace(v, REDACTED)
            return s
        out = map_strings(out, scrub)
    # 4. строки, похожие на ключи и пароли, тоже замазываются, печатаются только места
    suspicious = [(name, path) for path, s in leaves(out)
                  for name, rx in LEAK_PATTERNS.items() if rx.search(s)]
    if suspicious:
        def scrub_patterns(s):
            for rx in LEAK_PATTERNS.values():
                s = rx.sub(REDACTED, s)
            return s
        out = map_strings(out, scrub_patterns)
    left = [(name, path) for path, s in leaves(out)
            for name, rx in LEAK_PATTERNS.items() if rx.search(s)]

    flagged = {kind: [hide_people(p) for p in places] for kind, places in col.flagged.items()}
    dst = src.with_name(src.stem + ".sanitized.json")
    places_csv = src.with_name(src.stem + ".secret-places.csv")
    users_csv = src.with_name(src.stem + ".users.csv")
    for path in (dst, places_csv, users_csv):
        try:
            if path.exists():
                path.open("a").close()
        except PermissionError:
            sys.exit(f"Файл {path.name} открыт в другой программе (например, в Excel). "
                     "Закройте его и запустите скрипт снова.")
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    places_csv = src.with_name(src.stem + ".secret-places.csv")
    with places_csv.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["вид", "где"])
        for kind, places in flagged.items():
            for place in places:
                w.writerow([kind, place])
    users_csv = src.with_name(src.stem + ".users.csv")
    if pseudo.names:
        with users_csv.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["псевдоним", "настоящее имя"])
            for original, alias in pseudo.names.items():
                w.writerow([alias, original])

    kinds = ", ".join(f"{k} {n}" for k, n in col.kinds.most_common(8))
    print(f"Отчёт: {src.name} ({mb(src)}), скан {out['generationTime']}, Kubernetes {out['kubernetes']}")
    print()
    print("Что лежит в оригинале (только счётчики, значения не показываются):")
    print(f"  объектов в разделе resources: {sum(col.kinds.values())} ({kinds})")
    print(f"  объектов Secret: {col.stats['secrets']}")
    print(f"  переменных окружения с явно заданным значением: {col.stats['env_literal']}")
    if col.stats["env_masked"]:
        print(f"    из них значение скрыто сканером (XXXXXX): {col.stats['env_masked']}")
    print(f"  значений вида «password: …» внутри других значений: {len(col.kv_values)}")
    print(f"  паролей в адресах вида ://логин:пароль@: {len(col.url_passwords)}")
    print(f"  аннотаций last-applied-configuration (копия манифеста): {col.stats['last_applied']}")
    print(f"  людей в RBAC (пользователи и аккаунты с именами людей): {pseudo.counts['user']}, адресов почты: "
          f"{pseudo.counts['email']} (в выжимке заменены псевдонимами)")
    for kind, places in flagged.items():
        print()
        print(f"Похоже на секреты, {kind}: {len(places)}")
        for place in places[:SHOW]:
            print(f"  {place}")
        if len(places) > SHOW:
            print(f"  … и ещё {len(places) - SHOW}, полный список в {places_csv.name}")
    print()
    print(f"Выжимка: {dst.name} ({mb(dst)}): проверок {len(out['controls'])}, "
          f"находок {len(out['findings'])}")
    print(f"  сверено значений, похожих на секреты: {len(col.values)}")
    print(f"  встретились в выжимке и замазаны: {len(hits)}")
    for where, paths in list(hit_places.items())[:SHOW]:
        more = f" и ещё {len(paths) - 1}" if len(paths) > 1 else ""
        print(f"    {hide_people(where)} -> {paths[0]}{more}")
    print(f"  строк, похожих на ключи и пароли, замазано: {len(suspicious)}")
    for name, path in suspicious[:SHOW]:
        print(f"    {name}: {path}")
    print()
    if left:
        print("ИТОГ: в выжимке остались подозрительные строки. "
              "Не передавайте её, пока не разберёмся.")
    elif hits or suspicious:
        print("ИТОГ: выжимка чистая, подозрительные места замазаны (список выше). "
              "Её можно передавать для разбора.")
    else:
        print("ИТОГ: выжимка чистая, её можно передавать для разбора.")
    print(f"Где лежат секреты, без значений: {places_csv.name}")
    if pseudo.names:
        print(f"Файл {users_csv.name} (кто скрыт за псевдонимами) не передавайте.")
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())
