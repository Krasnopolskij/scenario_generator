import sys
import argparse
import time
import os
import datetime as dt
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Отложенные импорты после настройки sys.path
from data_collection import load_technique as techniques
from data_collection import load_capec as capec
from data_collection import load_cwe as cwe
from data_collection import load_cve as cve


def run_sequence(sequence):
    steps = {
        "techniques": techniques.load,
        "capec": capec.load,
        "cwe": cwe.load,
        "cve": cve.load,
    }
    start = time.time()
    for name in sequence:
        step_fn = steps[name]
        print(f"\n=== [{name.upper()}] Старт ===")
        t0 = time.time()
        step_fn()
        dt = time.time() - t0
        print(f"=== [{name.upper()}] Готово за {dt:.1f}с ===")
    print(f"\nВсе шаги завершены за {time.time() - start:.1f}с")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Заполнение Neo4j данными ATT&CK, CAPEC, CWE и CVE"
    )
    parser.add_argument(
        "--only",
        help="Список загрузчиков через запятую (techniques,capec,cwe,cve)",
    )
    parser.add_argument(
        "--skip",
        help="Список загрузчиков для пропуска через запятую (techniques,capec,cwe,cve)",
    )
    parser.add_argument(
        "--cve-from-year",
        help="Стартовый год для импорта CVE (включительно). Если не указан или некорректен — импорт за все годы.",
    )
    return parser.parse_args()


def main():
    load_dotenv()

    default_sequence = ["techniques", "capec", "cwe", "cve"]
    args = parse_args()

    if args.only:
        sequence = [s.strip() for s in args.only.split(",") if s.strip()]
    else:
        sequence = default_sequence

    if args.skip:
        to_skip = set(s.strip() for s in args.skip.split(",") if s.strip())
        sequence = [s for s in sequence if s not in to_skip]

    valid = {"techniques", "capec", "cwe", "cve"}
    unknown = [s for s in sequence if s not in valid]
    if unknown:
        print(f"Неизвестные загрузчики: {', '.join(unknown)}")
        print("Допустимые: techniques, capec, cwe, cve")
        sys.exit(2)

    try:
        # Ограничение стартового года импорта CVE через переменные окружения
        if getattr(args, "cve_from_year", None) is not None:
            raw = args.cve_from_year
            try:
                year = int(raw)
                current_year = dt.datetime.now(dt.UTC).year
                if 1999 <= year <= current_year:
                    os.environ["NVD_FROM_YEAR"] = str(year)
                else:
                    print(f"--cve-from-year проигнорирован (вне диапазона): {raw}. Импорт по всем годам.")
            except (TypeError, ValueError):
                if raw not in (None, ""):
                    print(f"--cve-from-year проигнорирован (не число): {raw}. Импорт по всем годам.")

        run_sequence(sequence)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
