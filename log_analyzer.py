#!/usr/bin/env python3

import argparse
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


# ============================================================
# REGEX
# ============================================================

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

FAILED_LOGIN = re.compile(
    rf"^(\w+\s+\d+\s+\d+:\d+:\d+).*?"
    rf"Failed password for (?:invalid user )?(\S+) "
    rf"from ({IP_REGEX})"
)

SUCCESS_LOGIN = re.compile(
    rf"^(\w+\s+\d+\s+\d+:\d+:\d+).*?"
    rf"Accepted \S+ for (\S+) "
    rf"from ({IP_REGEX})"
)

INVALID_USER = re.compile(
    rf"^(\w+\s+\d+\s+\d+:\d+:\d+).*?"
    rf"Invalid user (\S+) "
    rf"from ({IP_REGEX})"
)


# ============================================================
# DATA / TIME
# ============================================================

def parse_timestamp(timestamp):
    """
    Converte timestamp de log Linux para datetime.

    Logs tradicionais podem não informar o ano.
    Neste projeto usamos o ano atual.
    """

    current_year = datetime.now().year

    return datetime.strptime(
        f"{current_year} {timestamp}",
        "%Y %b %d %H:%M:%S"
    )


# ============================================================
# PARSER
# ============================================================

def parse_log_line(line):
    """
    Analisa uma linha do log e identifica o evento.
    """

    match = FAILED_LOGIN.search(line)

    if match:
        return {
            "timestamp": match.group(1),
            "usuario": match.group(2),
            "ip": match.group(3),
            "tipo": "LOGIN_FAILED",
        }

    match = SUCCESS_LOGIN.search(line)

    if match:
        return {
            "timestamp": match.group(1),
            "usuario": match.group(2),
            "ip": match.group(3),
            "tipo": "LOGIN_SUCCESS",
        }

    match = INVALID_USER.search(line)

    if match:
        return {
            "timestamp": match.group(1),
            "usuario": match.group(2),
            "ip": match.group(3),
            "tipo": "INVALID_USER",
        }

    return None


# ============================================================
# SEVERIDADE
# ============================================================

def get_severity(count):
    """
    Define a severidade com base na quantidade de falhas.
    """

    if count >= 20:
        return "CRITICAL"

    if count >= 10:
        return "HIGH"

    if count >= 5:
        return "WARNING"

    return "INFO"


# ============================================================
# BRUTE FORCE
# ============================================================

def detect_brute_force(events, threshold, window):
    """
    Detecta possíveis ataques de brute force.

    Regra:

        mesmo IP
        +
        threshold ou mais falhas
        +
        dentro da janela de tempo

    Gera apenas um alerta por IP.
    """

    failed_events = [
        event
        for event in events
        if event["tipo"] == "LOGIN_FAILED"
    ]

    alerts = []
    alerted_ips = set()

    for index, event in enumerate(failed_events):

        ip = event["ip"]

        if ip in alerted_ips:
            continue

        start_time = parse_timestamp(
            event["timestamp"]
        )

        count = 1
        users = {event["usuario"]}

        for next_event in failed_events[index + 1:]:

            if next_event["ip"] != ip:
                continue

            next_time = parse_timestamp(
                next_event["timestamp"]
            )

            elapsed = (
                next_time - start_time
            ).total_seconds()

            if elapsed <= window:
                count += 1
                users.add(next_event["usuario"])
            else:
                break

        if count >= threshold:

            alerts.append({
                "ip": ip,
                "count": count,
                "window": window,
                "users": sorted(users),
                "severity": get_severity(count),
            })

            alerted_ips.add(ip)

    return alerts


# ============================================================
# ANALISADOR
# ============================================================

def analyze_log(log_file, threshold, window):
    """
    Lê o arquivo e produz estatísticas.
    """

    events = []

    failed_logins = 0
    successful_logins = 0
    invalid_users = 0

    failed_ips = Counter()
    successful_ips = Counter()
    invalid_user_ips = Counter()

    try:

        with log_file.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line in file:

                event = parse_log_line(line)

                if event is None:
                    continue

                events.append(event)

                if event["tipo"] == "LOGIN_FAILED":

                    failed_logins += 1
                    failed_ips[event["ip"]] += 1

                elif event["tipo"] == "LOGIN_SUCCESS":

                    successful_logins += 1
                    successful_ips[event["ip"]] += 1

                elif event["tipo"] == "INVALID_USER":

                    invalid_users += 1
                    invalid_user_ips[event["ip"]] += 1

    except PermissionError:

        print(
            f"[ERRO] Sem permissão para ler: {log_file}"
        )

        sys.exit(1)

    except OSError as error:

        print(
            f"[ERRO] Não foi possível ler o arquivo: {error}"
        )

        sys.exit(1)

    suspicious_ips = {
        ip: count
        for ip, count in failed_ips.items()
        if count >= threshold
    }

    brute_force_alerts = detect_brute_force(
        events,
        threshold,
        window
    )

    return {
        "events": events,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "invalid_users": invalid_users,
        "failed_ips": failed_ips,
        "successful_ips": successful_ips,
        "invalid_user_ips": invalid_user_ips,
        "suspicious_ips": suspicious_ips,
        "brute_force_alerts": brute_force_alerts,
    }


# ============================================================
# RELATÓRIO
# ============================================================

def generate_report(
    log_file,
    results,
    threshold,
    window
):
    """
    Gera relatório textual da análise.
    """

    report = []

    report.append("=" * 60)
    report.append("LINUX LOG ANALYZER")
    report.append("=" * 60)

    report.append(
        f"Arquivo analisado: {log_file}"
    )

    report.append("")

    # --------------------------------------------------------
    # ESTATÍSTICAS
    # --------------------------------------------------------

    report.append("ESTATÍSTICAS")
    report.append("-" * 60)

    report.append(
        f"Login bem-sucedidos: {results['successful_logins']}"
    )

    report.append(
        f"Login falhos:        {results['failed_logins']}"
    )

    report.append(
        f"Usuários inválidos:  {results['invalid_users']}"
    )

    report.append(
        f"Eventos analisados:  {len(results['events'])}"
    )

    report.append("")

    # --------------------------------------------------------
    # IPS COM FALHAS
    # --------------------------------------------------------

    report.append("TOP IPS COM FALHAS")
    report.append("-" * 60)

    if results["failed_ips"]:

        for ip, count in results["failed_ips"].most_common(10):

            severity = get_severity(count)

            report.append(
                f"{ip:<20} "
                f"{count:>3} falhas "
                f"[{severity}]"
            )

    else:

        report.append(
            "Nenhuma falha encontrada."
        )

    report.append("")

    # --------------------------------------------------------
    # EVENTOS SUSPEITOS
    # --------------------------------------------------------

    report.append("EVENTOS SUSPEITOS")
    report.append("-" * 60)

    report.append(
        f"Threshold configurado: {threshold} falhas"
    )

    if results["suspicious_ips"]:

        for ip, count in sorted(
            results["suspicious_ips"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):

            severity = get_severity(count)

            report.append(
                f"[{severity}] {ip} -> {count} falhas"
            )

    else:

        report.append(
            "Nenhum IP atingiu o threshold."
        )

    report.append("")

    # --------------------------------------------------------
    # BRUTE FORCE
    # --------------------------------------------------------

    report.append("POSSÍVEL BRUTE FORCE")
    report.append("-" * 60)

    report.append(
        f"Janela de análise: {window} segundos"
    )

    if results["brute_force_alerts"]:

        for alert in results["brute_force_alerts"]:

            report.append(
                f"[{alert['severity']}] POSSÍVEL BRUTE FORCE"
            )

            report.append(
                f"IP: {alert['ip']}"
            )

            report.append(
                f"Falhas: {alert['count']}"
            )

            report.append(
                f"Janela: {alert['window']} segundos"
            )

            report.append(
                f"Usuários: {', '.join(alert['users'])}"
            )

            report.append("")

    else:

        report.append(
            "Nenhum possível brute force detectado."
        )

    report.append("=" * 60)

    return "\n".join(report)


# ============================================================
# ARGUMENTOS
# ============================================================

def parse_arguments():
    """
    Configura os argumentos da linha de comando.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Analisa logs Linux e identifica "
            "eventos suspeitos."
        )
    )

    parser.add_argument(
        "logfile",
        help="Caminho do arquivo de log."
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help=(
            "Número mínimo de falhas para "
            "considerar um IP suspeito. "
            "Padrão: 5"
        )
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help=(
            "Janela de tempo em segundos "
            "para detectar brute force. "
            "Padrão: 60"
        )
    )

    parser.add_argument(
        "--output",
        help=(
            "Arquivo onde o relatório será salvo."
        )
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_arguments()

    log_file = Path(args.logfile)

    # --------------------------------------------------------
    # VALIDAÇÕES
    # --------------------------------------------------------

    if not log_file.exists():

        print(
            f"[ERRO] Arquivo não encontrado: {log_file}"
        )

        sys.exit(1)

    if not log_file.is_file():

        print(
            f"[ERRO] O caminho não é um arquivo: {log_file}"
        )

        sys.exit(1)

    if args.threshold < 1:

        print(
            "[ERRO] O threshold deve ser maior que zero."
        )

        sys.exit(1)

    if args.window < 1:

        print(
            "[ERRO] A janela deve ser maior que zero."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # ANÁLISE
    # --------------------------------------------------------

    results = analyze_log(
        log_file,
        args.threshold,
        args.window
    )

    # --------------------------------------------------------
    # RELATÓRIO
    # --------------------------------------------------------

    report = generate_report(
        log_file,
        results,
        args.threshold,
        args.window
    )

    print(report)

    # --------------------------------------------------------
    # SALVAR RELATÓRIO
    # --------------------------------------------------------

    if args.output:

        output_file = Path(args.output)

        try:

            output_file.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            output_file.write_text(
                report,
                encoding="utf-8"
            )

            print(
                f"\n[+] Relatório salvo em: "
                f"{output_file}"
            )

        except OSError as error:

            print(
                "[ERRO] Não foi possível salvar "
                f"o relatório: {error}"
            )

            sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
