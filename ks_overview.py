#!/usr/bin/env python3
"""Общая картина по отчёту kubescape: состав проблем, разбор каждого типа, таблица ресурсов.

Принимает и сам отчёт kubescape, и выжимку ks_sanitize.py. Из отчёта читаются
только сводка по проверкам (summaryDetails) и находки (results): раздел resources
с копиями объектов кластера, где лежат пароли и токены, не открывается.

Запуск:
  python ks_overview.py cis-v1.12.0-proxy.json                 # локально, с именами как есть
  python ks_overview.py cis-v1.12.0-proxy.json --top 40 --csv
  python ks_overview.py cis-v1.12.0-proxy.json --pseudonyms    # версия для передачи
  python ks_overview.py cis-v1.12.0-proxy.sanitized.json       # по готовой выжимке

Рядом появится cis-v1.12.0-proxy.overview.md. Если в отчёте остались настоящие
логины, файл называется .overview-names.md — такой наружу не передавать; с
--pseudonyms логины людей заменяются на user-NN и выходит обычный .overview.md.
С --csv рядом лягут ещё две простые таблицы: .checks.csv (типы проблем со всеми
описаниями) и .resources.csv (ресурс и его проблемы) — для Excel или LibreOffice.

Описание и рекомендация по каждой проверке берутся из офлайн-артефакта kubescape
(artifacts/<фреймворк>.json) — это официальный текст библиотеки проверок; рядом
наш разбор: что это значит здесь, на что влияет и что сделать.
"""

import argparse
import csv
import json
import re
import sys
import textwrap
from collections import Counter, defaultdict
from pathlib import Path

from ks_notes import (CONTROL_IMPACT, CONTROL_NOTES, PRIORITY_ORDER, PSEUDO, SEVERITY_ORDER,
                      SEVERITY_RU, SKIPPED_NOTE, SUBJECT_KINDS, cis_parts, load_names, zone_of)
from ks_sanitize import Pseudonyms, build_findings, control_summary

WIDTH = 100          # ширина абзаца на экране
CONSOLE_ROWS = 25    # сколько строк длинных таблиц показывать на экране

IMPACT_DEFAULT = ("Влияние смотреть по официальному описанию ниже: разбора на русском для этой "
                  "проверки ещё нет — допишите в CONTROL_IMPACT в ks_notes.py.")
NOTE_DEFAULT = ("Разбора на русском для этой проверки ещё нет — смотрите официальное описание "
                "и допишите в CONTROL_NOTES в ks_notes.py.")
SKIPPED_IMPACT = ("Проверка не выполнялась, поэтому состояние неизвестно: считать её ни "
                  "пройденной, ни непройденной нельзя.")
FIX_NOISE = re.compile(r"seLinuxOptions|fsGroupChangePolicy")
SEVERITY_LIST = ["критическая", "высокая", "средняя", "низкая"]
STATUS_TITLE = {"failed": "не пройдено", "passed": "пройдено", "skipped": "не проверялось"}


def setup_console():
    """Кириллица на экране Windows: кодовая страница 65001 и вывод в UTF-8."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


class Report:
    """Текст сразу в двух видах: на экран и в файл Markdown."""

    def __init__(self, restore=lambda s: s):
        self.md, self.txt, self.restore = [], [], restore

    def _both(self, md_line, txt_line=None):
        self.md.append(md_line)
        self.txt.append(md_line if txt_line is None else txt_line)

    def title(self, text):
        self._both(f"# {text}", f"{text}\n{'=' * min(len(text), WIDTH)}")
        self.blank()

    def head(self, text, level=2):
        line = self.restore(text)
        self._both(f"{'#' * level} {line}", line if level == 3 else f"{line}\n{'-' * min(len(line), WIDTH)}")
        self.blank()

    def blank(self):
        self._both("")

    def para(self, text, indent=""):
        text = self.restore(text)
        self.md.append(text if not indent else f"{indent}{text}")
        self.txt.extend(textwrap.wrap(text, WIDTH, initial_indent=indent,
                                      subsequent_indent=indent + "  ") or [""])
        self.blank()

    def field(self, name, value):
        """Строка «Название: значение» — в файле пунктом списка."""
        value = self.restore(str(value))
        self.md.append(f"- **{name}:** {value}")
        self.txt.extend(textwrap.wrap(f"{name}: {value}", WIDTH, subsequent_indent="    ") or [""])

    def bullet(self, text):
        text = self.restore(text)
        self.md.append(f"- {text}")
        self.txt.extend(textwrap.wrap(text, WIDTH, initial_indent="  - ",
                                      subsequent_indent="    ") or [""])

    def table(self, headers, rows, console_limit=None, note=None):
        rows = [[self.restore(str(c)) for c in r] for r in rows]
        self.md.append("| " + " | ".join(headers) + " |")
        self.md.append("|" + "|".join("---" for _ in headers) + "|")
        for r in rows:
            self.md.append("| " + " | ".join(c.replace("|", "\\|") for c in r) + " |")
        self.md.append("")

        shown = rows if console_limit is None else rows[:console_limit]
        widths = [max(len(h), *(len(r[i]) for r in shown)) if shown else len(h)
                  for i, h in enumerate(headers)]
        widths = [min(w, 60) for w in widths]

        def line(cells):
            return "  ".join(c[:w].ljust(w) if len(c) <= w else (c[:w - 1] + "…").ljust(w)
                             for c, w in zip(cells, widths)).rstrip()

        self.txt.append(line(headers))
        self.txt.append("  ".join("-" * w for w in widths))
        self.txt.extend(line(r) for r in shown)
        if console_limit is not None and len(rows) > console_limit:
            self.txt.append(f"… ещё {len(rows) - console_limit} строк — целиком в файле отчёта")
        if note:
            self.txt.append(note)
            self.md.append(note)
            self.md.append("")
        self.txt.append("")

    def dump(self, path):
        path.write_text("\n".join(self.md).rstrip() + "\n", encoding="utf-8")
        print("\n".join(self.txt))


class KeepNames:
    """Заглушка вместо псевдонимов: при локальном запуске имена нужны как есть."""

    def get(self, original, prefix):
        return original


def load_report(path, pseudonyms):
    """Сводка и находки из отчёта kubescape или из готовой выжимки.

    Возвращает (данные, есть_ли_настоящие_имена).
    """
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        sys.exit("Это не JSON-отчёт kubescape.")
    if "controls" in data and "findings" in data:
        return data, False  # выжимка ks_sanitize.py: имена уже заменены
    if "summaryDetails" not in data:
        sys.exit("Это не отчёт kubescape и не выжимка ks_sanitize.py: нет раздела summaryDetails.")

    sd = data["summaryDetails"]
    pseudo = Pseudonyms() if pseudonyms else KeepNames()
    out = {
        "source": "kubescape",
        "generationTime": data.get("generationTime", ""),
        "kubernetes": (data.get("clusterAPIServerInfo") or {}).get("gitVersion", ""),
        "complianceScore": round(sd.get("complianceScore") or 0, 1),
        "frameworks": [{"name": f.get("name", ""), "version": f.get("version", ""),
                        "complianceScore": round(f.get("complianceScore") or 0, 1)}
                       for f in sd.get("frameworks") or [] if isinstance(f, dict)],
        "controls": sorted((control_summary(cid, c)
                            for cid, c in (sd.get("controls") or {}).items() if isinstance(c, dict)),
                           key=lambda c: c["id"]),
        "findings": build_findings(data.get("results") or [], pseudo),
    }
    if not out["frameworks"]:
        out["frameworks"] = [{"name": path.stem.split(".")[0], "version": "", "complianceScore": 0}]
    return out, not pseudonyms


def find_framework(src, name, explicit):
    """Офлайн-артефакт kubescape с официальными описаниями проверок."""
    if explicit:
        return Path(explicit)
    for base in (src.parent, src.parent.parent, src.parent.parent.parent):
        for cand in (base / "artifacts" / f"{name}.json", base / f"{name}.json"):
            # рядом с отчётом бывает пустой файл с тем же именем от неудачного прогона
            if cand.exists() and cand.stat().st_size > 1000 and cand.resolve() != src:
                return cand
    return None


def load_official(path):
    """controlID -> официальные описание, рекомендация, категория, шаги атаки."""
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError:
        return {}
    out = {}
    for c in data.get("controls") or []:
        tracks = []
        for t in (c.get("attributes") or {}).get("attackTracks") or []:
            tracks += t.get("categories") or []
        out[c["controlID"]] = {
            "description": " ".join((c.get("description") or "").split()),
            "remediation": " ".join((c.get("remediation") or "").split()),
            "tracks": sorted(dict.fromkeys(tracks)),
            "baseScore": c.get("baseScore"),
        }
    return out


def note_of(cid):
    """Приоритет, кто исправляет, что не так, что сделать."""
    return CONTROL_NOTES.get(cid, ("—", "—", NOTE_DEFAULT, "—"))


def severity_ru(control):
    return SEVERITY_RU.get(control.get("severity"), control.get("severity") or "—")


def fix_hints(findings, limit=3):
    """Самые частые поля, которые правятся по этой проверке."""
    counts = Counter()
    for f in findings:
        paths = f.get("paths") or {}
        for x in paths.get("fix") or []:
            if x.get("value") != "YOUR_VALUE" and not FIX_NOISE.search(x["path"]):
                counts[f"{x['path']} = {x['value']}"] += 1
        for x in paths.get("delete") or []:
            counts[f"удалить {x}"] += 1
        for x in paths.get("review") or []:
            counts[f"проверить {x}"] += 1
        if not (paths.get("fix") or paths.get("delete") or paths.get("review")):
            for x in paths.get("failed") or []:
                counts[f"поле {x}"] += 1
    return [p for p, _ in counts.most_common(limit)]


def where_hint(findings, limit=5):
    """Топ namespace, в которых находки этой проверки."""
    counts = Counter(f["namespace"] or "(кластер)" for f in findings)
    parts = [f"{ns} ({n})" for ns, n in counts.most_common(limit)]
    tail = len(counts) - len(parts)
    return ", ".join(parts) + (f" и ещё {tail}" if tail > 0 else "")


def build(data, official, rep, top):
    controls = {c["id"]: c for c in data["controls"]}
    findings = data["findings"]
    failed_f = [f for f in findings if f["status"] == "failed"]
    by_control = defaultdict(list)
    for f in failed_f:
        by_control[f["control"]].append(f)

    # ресурс -> проверки, по которым он не прошёл
    resources = defaultdict(set)
    roles_of = defaultdict(set)
    for f in failed_f:
        key = (f["kind"], f["namespace"], f["name"])
        resources[key].add(f["control"])
        if f.get("role"):
            roles_of[key].add(f["role"])

    def sev_of(cid):
        return severity_ru(controls.get(cid, {}))

    def worst(cids):
        return min((sev_of(c) for c in cids), key=lambda s: SEVERITY_ORDER.get(s, 9))

    by_status = Counter(c["status"] for c in controls.values())
    failed_controls = [c for c in controls.values() if c["status"] == "failed"]
    skipped_controls = [c for c in controls.values() if c["status"] == "skipped"]

    # ---- шапка
    rep.title("Отчёт kubescape: общая картина")
    rep.field("Сканер", f"{data.get('source', 'kubescape')}, фреймворк {data['frameworks'][0]['name']}")
    rep.field("Kubernetes", data.get("kubernetes") or "—")
    rep.field("Дата сканирования", (data.get("generationTime") or "—").replace("T", " ").rstrip("Z"))
    rep.field("Соответствие фреймворку", f"{data.get('complianceScore')}%")
    rep.field("Проверок", ", ".join(f"{STATUS_TITLE.get(s, s)} {n}"
                                    for s, n in sorted(by_status.items())) + f"; всего {len(controls)}")
    rep.field("Находок со статусом «не пройдено»", f"{len(failed_f)} на {len(resources)} ресурсах")
    rep.field("Исключения", f"{sum(1 for f in findings if f.get('subStatus') == 'w/exceptions')} "
                            "находок закрыты правилами исключений kubescape")
    rep.blank()
    rep.para("Счётчики kubescape: ignoredResources входит в passedResources, поэтому в столбце "
             "«пройдено» могут стоять ресурсы, которые проверку не проходили. Ниже такие "
             "оговорены отдельно.")

    # ---- критичность
    rep.head("Состав проблем по критичности")
    rows = []
    for sev in SEVERITY_LIST:
        cids = [c["id"] for c in failed_controls if severity_ru(c) == sev]
        if not cids:
            continue
        res = {k for k, v in resources.items() if v & set(cids)}
        fnd = sum(len(by_control[c]) for c in cids)
        rows.append([sev, len(cids), len(res), fnd,
                     f"{fnd * 100 // max(len(failed_f), 1)}%"])
    rep.table(["Критичность", "Непройденных проверок", "Ресурсов затронуто", "Находок", "Доля находок"],
              rows, note="Критичность — из отчёта kubescape (по scoreFactor проверки).")

    rep.head("Состав по приоритету работ")
    rows = []
    for prio in sorted({note_of(c["id"])[0] for c in failed_controls},
                       key=lambda p: PRIORITY_ORDER.get(p, 9)):
        cids = [c["id"] for c in failed_controls if note_of(c["id"])[0] == prio]
        res = {k for k, v in resources.items() if v & set(cids)}
        who = sorted({part.strip() for c in cids for part in note_of(c)[1].split(",")} - {"—"})
        rows.append([prio, len(cids), len(res), sum(len(by_control[c]) for c in cids),
                     ", ".join(who) or "—"])
    rep.table(["Приоритет", "Проверок", "Ресурсов", "Находок", "Кто исправляет"], rows,
              note="Приоритет — наш, из разбора в ks_notes.py: P1 делать сразу, «инфо» — к сведению.")

    rep.head("Состав по разделам CIS")
    rows = []
    groups = defaultdict(list)
    for c in failed_controls:
        groups[(c.get("category") or "—", c.get("subcategory") or "")].append(c["id"])
    for (cat, sub), cids in sorted(groups.items(), key=lambda kv: -sum(len(by_control[c])
                                                                      for c in kv[1])):
        rows.append([cat, sub or "—", len(cids), sum(len(by_control[c]) for c in cids),
                     ", ".join(sorted(cids)[:6]) + (" …" if len(cids) > 6 else "")])
    rep.table(["Раздел", "Подраздел", "Проверок", "Находок", "Проверки"], rows)

    rep.head("Типы выявленных проблем")
    rep.para("По каждой непройденной проверке: что это, на что влияет и что сделать. "
             "«Официально» — текст библиотеки проверок kubescape, остальное — наш разбор.")
    order = sorted(failed_controls,
                   key=lambda c: (SEVERITY_ORDER.get(severity_ru(c), 9),
                                  PRIORITY_ORDER.get(note_of(c["id"])[0], 9),
                                  -len(by_control[c["id"]])))
    checks = []  # та же таблица типов проблем, но строками — для CSV
    for c in order:
        cid = c["id"]
        prio, who, what, fix = note_of(cid)
        num, name = cis_parts(c["name"])
        off = official.get(cid, {})
        items = by_control[cid]
        checks.append([cid, f"CIS-{num}", name, severity_ru(c), prio, who,
                       c["failed"], c["failed"] + c["passed"], c.get("ignored", 0), len(items),
                       what, CONTROL_IMPACT.get(cid, IMPACT_DEFAULT), fix,
                       off.get("description", ""), off.get("remediation", ""),
                       "; ".join(fix_hints(items)), where_hint(items)])
        rep.head(f"{cid} · CIS-{num} · {severity_ru(c)} критичность · {prio}", level=3)
        rep.para(f"*{name}*" if name else "")
        total = c["failed"] + c["passed"]
        counted = f"{c['failed']} из {total} проверенных ресурсов"
        if c.get("ignored"):
            counted += f"; {c['ignored']} ресурсов kubescape посчитал пройденными по исключениям"
        rep.field("Затронуто", counted)
        rep.field("Исправляет", who)
        rep.field("Что это", what)
        rep.field("На что влияет", CONTROL_IMPACT.get(cid, IMPACT_DEFAULT))
        if off.get("tracks"):
            rep.field("Шаг атаки по kubescape", ", ".join(off["tracks"]))
        rep.field("Что сделать", fix)
        if off.get("description"):
            rep.field("Официально", off["description"])
        if off.get("remediation"):
            rep.field("Официальная рекомендация", off["remediation"][:400])
        hints = fix_hints(items)
        if hints:
            rep.field("Типовые поля в находках", "; ".join(hints))
        rep.field("Где", where_hint(items))
        rep.blank()

    # ---- пропущенные
    if skipped_controls:
        rep.head("Проверки, которые не выполнялись")
        _, who, what, fix = SKIPPED_NOTE
        rep.field("Сколько", f"{len(skipped_controls)} из {len(controls)}")
        rep.field("Почему", what)
        rep.field("На что влияет", SKIPPED_IMPACT)
        rep.field("Что сделать", fix)
        rep.field("Исправляет", who)
        rep.blank()
        reasons = Counter(" ".join((c.get("skipReason") or "причина не указана").split())
                          for c in skipped_controls)
        rep.table(["Причина из отчёта", "Проверок"],
                  [[r[:120], n] for r, n in reasons.most_common()])
        rows = [[c["id"], f"CIS-{cis_parts(c['name'])[0]}", cis_parts(c["name"])[1]]
                for c in sorted(skipped_controls, key=lambda c: c["id"])]
        rep.table(["Проверка", "Пункт CIS", "Название"], rows, console_limit=CONSOLE_ROWS)

    # ---- ресурсы
    rep.head("Ресурсы и их проблемы")
    rep.para(f"Ресурсов с непройденными проверками: {len(resources)}. "
             f"На экране — {top} самых проблемных, в файле отчёта таблица целиком.")
    rows = []
    for (kind, ns, name), cids in resources.items():
        sev = worst(cids)
        note = ""
        if kind in SUBJECT_KINDS and roles_of[(kind, ns, name)]:
            roles = sorted(roles_of[(kind, ns, name)])
            note = "роли: " + ", ".join(roles[:3]) + (f" и ещё {len(roles) - 3}"
                                                      if len(roles) > 3 else "")
        rows.append([kind, ns or "—", name, zone_of(ns), sev, len(cids),
                     ", ".join(sorted(cids)), note])
    rows.sort(key=lambda r: (-r[5], SEVERITY_ORDER.get(r[4], 9), r[0], r[2]))
    rep.table(["Тип", "Namespace", "Имя", "Зона", "Макс. критичность", "Проблем", "Проверки",
               "Примечание"], rows, console_limit=top)

    rep.head("Сводка по namespace")
    ns_rows = []
    for ns in sorted({ns for _, ns, _ in resources}):
        keys = [k for k in resources if k[1] == ns]
        cids = set().union(*(resources[k] for k in keys))
        ns_rows.append([ns or "(объекты уровня кластера)", zone_of(ns), len(keys),
                        sum(len(resources[k]) for k in keys), worst(cids)])
    ns_rows.sort(key=lambda r: -r[3])
    rep.table(["Namespace", "Зона", "Ресурсов с проблемами", "Проблем (ресурс × проверка)",
               "Макс. критичность"], ns_rows, console_limit=top)

    # ---- план: проверки с одинаковой рекомендацией идут одним пунктом
    rep.head("Что делать в первую очередь")
    todo = [c for c in order if note_of(c["id"])[0] == "P1"]
    if not todo:
        rep.para("Проверок с приоритетом P1 не выявлено.")
    steps = defaultdict(list)
    for c in todo:
        steps[note_of(c["id"])[3]].append(c)
    for fix, group in steps.items():
        tag = ", ".join(f"{c['id']} (CIS-{cis_parts(c['name'])[0]})" for c in group)
        who = note_of(group[0]["id"])[1]
        rep.bullet(f"{tag} — {who}, {worst({c['id'] for c in group})} критичность: {fix}")
    rep.blank()
    rep.para("Отдельно: пропущенные проверки закрываются одним прогоном kube-bench на узлах — "
             "без этого треть фреймворка остаётся неизвестной.")
    return {"resources": rows, "checks": checks}


CSV_HEADERS = {
    "resources": ["Тип", "Namespace", "Имя", "Зона", "Макс. критичность", "Проблем", "Проверки",
                  "Примечание"],
    "checks": ["Проверка", "Пункт CIS", "Название", "Критичность", "Приоритет", "Исправляет",
               "Не прошли", "Проверено ресурсов", "Из них по исключениям", "Находок", "Что это",
               "На что влияет", "Что сделать", "Официальное описание",
               "Официальная рекомендация", "Типовые поля в находках", "Где"],
}


def write_csv(path, kind, rows, restore):
    """Простая таблица с разделителем «;» — открывается Excel и LibreOffice без модулей."""
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(CSV_HEADERS[kind])
        for row in rows:
            w.writerow([" ".join(restore(str(c)).split()) for c in row])


def main():
    ap = argparse.ArgumentParser(
        description="Общая картина по отчёту kubescape: состав проблем, разбор типов, ресурсы.")
    ap.add_argument("report", help="отчёт kubescape *.json или выжимка *.sanitized.json")
    ap.add_argument("--framework", help="артефакт kubescape с описаниями (по умолчанию ищется "
                                        "рядом в artifacts/)")
    ap.add_argument("--pseudonyms", action="store_true",
                    help="заменить логины людей на user-NN: версия отчёта для передачи")
    ap.add_argument("--names", help="*.users.csv от ks_sanitize.py: вернуть настоящие имена "
                                    "в отчёт, собранный по выжимке")
    ap.add_argument("--out", help="файл отчёта (по умолчанию *.overview.md рядом с отчётом)")
    ap.add_argument("--top", type=int, default=CONSOLE_ROWS,
                    help=f"сколько строк таблиц показывать на экране (по умолчанию {CONSOLE_ROWS})")
    ap.add_argument("--csv", action="store_true",
                    help="ещё и таблицы в CSV: *.checks.csv (типы проблем) и *.resources.csv")
    args = ap.parse_args()
    setup_console()

    src = Path(args.report).resolve()
    data, real_names = load_report(src, args.pseudonyms)
    base = src.name.removesuffix(".json").removesuffix(".sanitized")
    names = load_names(args.names) if args.names else {}
    real_names = real_names or bool(names)
    dst = Path(args.out) if args.out else src.with_name(
        base + (".overview-names.md" if real_names else ".overview.md"))

    fw = find_framework(src, data["frameworks"][0]["name"], args.framework)
    official = load_official(fw)

    def restore(s):
        return PSEUDO.sub(lambda m: names.get(m.group(0), m.group(0)), s) if names else s

    rep = Report(restore)
    tables = build(data, official, rep, args.top)
    rep.para("Отчёт собран по сводке проверок и находкам: копии объектов кластера (раздел "
             "resources, где лежат пароли и токены) не читались, значений секретов здесь нет."
             + (" Логины людей — настоящие." if real_names else
                " Логины людей заменены псевдонимами user-NN."))
    rep.dump(dst)
    print(f"Отчёт: {dst}")
    if not official:
        print("Официальные описания не подключены: не нашёлся артефакт "
              f"{data['frameworks'][0]['name']}.json — укажите --framework.")
    if args.csv:
        tail = "-names.csv" if real_names else ".csv"
        for kind, title in (("checks", "Таблица проверок"), ("resources", "Таблица ресурсов")):
            csv_path = dst.with_name(f"{base}.{kind}{tail}")
            write_csv(csv_path, kind, tables[kind], restore)
            print(f"{title}: {csv_path}")
    if real_names:
        print("В файлах настоящие логины — наружу не передавать; версия для передачи: "
              "--pseudonyms.")


if __name__ == "__main__":
    main()
