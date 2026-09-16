#!/usr/bin/env python3
"""Показать команду запуска и переменные окружения одного ресурса из отчёта kubescape.

Нужен, чтобы своими глазами проверить места из *.secret-places.csv.
Печатает значения как есть: запускайте у себя в терминале и не пересылайте вывод.

Запуск:  python ks_show.py cis-v1.12.0-proxy.json myapp/api
Вместо namespace/имя можно указать только имя.
"""

import json
import sys
from pathlib import Path


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 3:
        sys.exit("Запуск: python ks_show.py <отчёт.json> <namespace/имя>")
    report, target = Path(sys.argv[1]), sys.argv[2]
    data = json.loads(report.read_text(encoding="utf-8-sig"))
    found = False
    for item in data.get("resources") or []:
        obj = item.get("object", item)
        meta = obj.get("metadata") or {}
        full = f"{meta.get('namespace') or '-'}/{meta.get('name')}"
        if target not in (full, meta.get("name")):
            continue
        spec = ((obj.get("spec") or {}).get("template") or {}).get("spec") or obj.get("spec") or {}
        if not (spec.get("containers") or spec.get("initContainers")):
            continue  # Service, Secret и прочие объекты с тем же именем: контейнеров у них нет
        found = True
        print(f"\n{obj.get('kind')} {full}")
        print(f"  resourceID в отчёте: {item.get('resourceID')}")
        for key in ("initContainers", "containers"):
            for i, c in enumerate(spec.get(key) or []):
                print(f"\n  {key}[{i}] — контейнер {c.get('name')}")
                for part in ("command", "args"):
                    for j, arg in enumerate(c.get(part) or []):
                        print(f"    {part}[{j}] = {arg}")
                for e in c.get("env") or []:
                    if "value" in e:
                        print(f"    env {e.get('name')} = {e['value']}")
                    else:
                        ref = json.dumps(e.get("valueFrom"), ensure_ascii=False)
                        print(f"    env {e.get('name')} ← ссылка {ref}")
    if not found:
        sys.exit(f"Приложение {target} с контейнерами в разделе resources не найдено.")


if __name__ == "__main__":
    main()
