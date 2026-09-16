#!/usr/bin/env bash
# Меню для разбора отчётов kubescape: выбрал отчёт, выбрал действие, получил результат.
# Под капотом вызываются ks_overview.py, ks_report.py, ks_sanitize.py и ks_show.py.
#
# Запуск:  ./ks.sh
# Отчёты кладите рядом со скриптом (можно в подпапках по кластерам) — скрипт их
# найдёт сам и предложит выбрать в меню.

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

ROOTS=("$HERE")  # отчёты ищем только рядом со скриптом
DEPTH=6          # и в подпапках: удобно держать по папке на кластер

REPORT=""          # выбранный отчёт
NAMES="настоящие"  # настоящие | псевдонимы
TOP=25             # строк длинных таблиц на экране
CSV="нет"          # добавлять ли таблицу ресурсов в CSV

die() { printf '%s\n' "$*" >&2; exit 1; }

ask() {  # ask <переменная> <приглашение>; 1, если ввод кончился
  local __var="$1"
  read -rp "$2" "$__var" || { printf '\n'; return 1; }
}

find_python() {
  local c
  for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then
      PY="$c"
      return
    fi
  done
  die "Не нашёлся Python 3 — поставьте его и запустите снова."
}

# --- выбор отчёта -----------------------------------------------------------

list_reports() {
  local root
  for root in "$@"; do
    [ -d "$root" ] || continue
    find "$root" -maxdepth "$DEPTH" -type f \
      \( -name 'cis-*.json' -o -name '*kubescape*.json' -o -name '*.sanitized.json' \) \
      -size +20k 2>/dev/null | grep -v '/artifacts/'
  done | sort -u
}

label_of() {  # подпись: папка/файл, размер, дата
  local f="$1" base parent size date
  [ -n "$f" ] || { printf 'не выбран'; return; }
  base="${f##*/}"
  parent="${f%/*}"; parent="${parent##*/}"
  size=$(du -m "$f" 2>/dev/null | cut -f1)
  date=$(date -r "$f" '+%d.%m.%Y' 2>/dev/null)
  printf '%s/%s  (%s МБ, %s)' "$parent" "$base" "${size:-?}" "${date:-?}"
}

choose_report() {
  local -a found=()
  local line
  while IFS= read -r line; do [ -n "$line" ] && found+=("$line"); done < <(list_reports "${ROOTS[@]}")

  printf '\nОтчёты kubescape рядом со скриптом (%s):\n' "$HERE"
  if [ ${#found[@]} -eq 0 ]; then
    printf '  ничего не нашлось — положите файл отчёта (*.json) в эту папку\n'
    printf '  или в подпапку по кластеру и запустите скрипт снова.\n'
    return 2
  fi
  local i
  for i in "${!found[@]}"; do
    printf '  %2d) %s\n' "$((i + 1))" "$(label_of "${found[$i]}")"
  done

  local answer
  ask answer $'\nНомер отчёта (Enter — выход): ' || return 2
  case "$answer" in
    "") return 2;;
    *) if [[ "$answer" =~ ^[0-9]+$ ]] && [ "$answer" -ge 1 ] && [ "$answer" -le ${#found[@]} ]; then
         REPORT="${found[$((answer - 1))]}"
       else
         printf 'Нет такого номера.\n'; return 1
       fi;;
  esac
  [ -f "$REPORT" ] || { printf 'Файла нет: %s\n' "$REPORT"; REPORT=""; return 1; }
}

pick_report() {  # спрашивать, пока не выберут; Enter или конец ввода — выход
  while [ -z "$REPORT" ]; do
    choose_report
    [ $? -eq 2 ] && return 1
  done
  return 0
}

# --- запуск скриптов --------------------------------------------------------

pager() {  # длинный вывод листаем, короткий печатаем как есть
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then
    less -R -X -F
  else
    cat
  fi
}

flag_names() { [ "$NAMES" = "псевдонимы" ] && printf '%s' "--pseudonyms"; }

sanitized_of() {  # выжимка для ks_report.py: если её нет или она старше — делаем
  local src="$1" out
  case "$src" in
    *.sanitized.json) printf '%s' "$src"; return;;
  esac
  out="${src%.json}.sanitized.json"
  if [ ! -f "$out" ] || [ "$src" -nt "$out" ]; then
    printf 'Готовлю выжимку (нужна для таблицы): %s\n' "${out##*/}" >&2
    "$PY" "$HERE/ks_sanitize.py" "$src" >&2 || return 1
  fi
  printf '%s' "$out"
}

do_overview() {
  local -a cmd=("$PY" "$HERE/ks_overview.py" "$REPORT" --top "$TOP")
  [ "$CSV" = "да" ] && cmd+=(--csv)
  local f; f="$(flag_names)"; [ -n "$f" ] && cmd+=("$f")
  printf '\n$ %s\n\n' "${cmd[*]}"
  "${cmd[@]}" 2>&1 | pager
}

do_report_xlsx() {
  local san; san="$(sanitized_of "$REPORT")" || return 1
  local -a cmd=("$PY" "$HERE/ks_report.py" "$san")
  if [ "$NAMES" = "настоящие" ]; then
    local users="${san%.sanitized.json}.users.csv"
    [ -f "$users" ] && cmd+=(--names "$users")
  fi
  printf '\n$ %s\n\n' "${cmd[*]}"
  "${cmd[@]}" 2>&1 | tail -20
}

do_sanitize() {
  case "$REPORT" in
    *.sanitized.json) printf 'Это уже выжимка.\n'; return;;
  esac
  printf '\n$ %s %s/ks_sanitize.py %s\n\n' "$PY" "$HERE" "$REPORT"
  "$PY" "$HERE/ks_sanitize.py" "$REPORT" 2>&1 | pager
}

do_show() {
  case "$REPORT" in
    *.sanitized.json)
      printf 'Нужен сам отчёт kubescape, а не выжимка: в выжимке значений нет.\n'; return;;
  esac
  printf 'Вывод покажет настоящие значения переменных и аргументов — не пересылайте его.\n'
  local target
  ask target 'Ресурс (namespace/имя или просто имя): ' || return
  [ -n "$target" ] || return
  "$PY" "$HERE/ks_show.py" "$REPORT" "$target" 2>&1 | pager
}

list_results() {
  local dir="${REPORT%/*}" base="${REPORT##*/}"
  base="${base%.json}"; base="${base%.sanitized}"
  printf '\nФайлы разбора в %s:\n' "$dir"
  ls -lh "$dir" 2>/dev/null | grep -E "${base}\.(overview|analysis|resources|sanitized|secret-places|users)" \
    || printf '  пока ничего не собрано\n'
  command -v xdg-open >/dev/null 2>&1 && xdg-open "$dir" >/dev/null 2>&1 &
}

toggle_names() { [ "$NAMES" = "настоящие" ] && NAMES="псевдонимы" || NAMES="настоящие"; }
toggle_csv() { [ "$CSV" = "нет" ] && CSV="да" || CSV="нет"; }

set_top() {
  local answer
  ask answer 'Сколько строк таблиц показывать на экране: ' || return
  [[ "$answer" =~ ^[0-9]+$ ]] && TOP="$answer" || printf 'Оставил %s.\n' "$TOP"
}

# --- меню -------------------------------------------------------------------

menu() {
  printf '\n==================== Разбор отчётов kubescape ====================\n'
  printf 'Отчёт: %s\n' "$(label_of "$REPORT")"
  printf 'Имена людей: %s   Строк на экране: %s   Таблица ресурсов в CSV: %s\n' "$NAMES" "$TOP" "$CSV"
  cat <<'MENU'
------------------------------------------------------------------
  1) Общая картина: критичность, типы проблем, ресурсы -> экран и .md
  2) Таблица разбора .xlsx (Сводка, План, Проверки, Находки, RBAC)
  3) Выжимка для передачи наружу (*.sanitized.json + где лежат секреты)
  4) Команда и переменные одного ресурса (значения как есть, не пересылать)
  5) Показать собранные файлы разбора

  и) Имена людей: настоящие / псевдонимы
  с) Таблица ресурсов в CSV: да / нет
  т) Сколько строк таблиц показывать на экране
  о) Выбрать другой отчёт
  0) Выход
------------------------------------------------------------------
MENU
}

main() {
  find_python
  [ -f "$HERE/ks_overview.py" ] || die "Рядом нет ks_overview.py: держите ks.sh в папке со скриптами."
  pick_report || { printf 'Отчёт не выбран.\n'; return 0; }

  local choice
  while true; do
    menu
    ask choice 'Что сделать: ' || return 0
    case "$choice" in
      1) do_overview;;
      2) do_report_xlsx;;
      3) do_sanitize;;
      4) do_show;;
      5) list_results;;
      и|И|i|I|n|N) toggle_names;;
      с|С|c|C) toggle_csv;;
      т|Т|t|T) set_top;;
      о|О|o|O|r|R) REPORT=""; pick_report || return 0;;
      0|q|Q|"") printf 'Готово.\n'; return 0;;
      *) printf 'Нет такого пункта.\n';;
    esac
  done
}

main
