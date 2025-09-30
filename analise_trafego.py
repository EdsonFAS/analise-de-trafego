#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys
import re
import csv
from collections import defaultdict, deque

TCPDUMP_CMD = shutil.which("tcpdump")
TSHARK_CMD = shutil.which("tshark")

LINE_RE = re.compile(r'^\s*([\d\.:]+)\s+(.*?)$')
# We'll search later for "SRC.PORT > DST.PORT:" pattern inside the remainder
ADDR_RE = re.compile(r'IP\s+(?P<src>[\d\.]+\d+)\s+>\s+(?P<dst>[\d\.]+\d+)')

def run_capture(interface, duration, out_file):
    if TCPDUMP_CMD:
        cmd = ["sudo", TCPDUMP_CMD, "-i", interface, "-nn", "-ttt", "tcp or udp", "-l"]
    elif TSHARK_CMD:
        cmd = ["sudo", TSHARK_CMD, "-i", interface, "-l", "-n", "-Y", "ip"]
    else:
        raise RuntimeError("tcpdump e tshark não encontrados no PATH. Instale um deles.")

    print(f"[i] Iniciando captura por {duration}s com: {' '.join(cmd)}")
    with open(out_file, "w", encoding="utf-8", errors="replace") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)
        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    print(f"[i] Captura finalizada. Arquivo: {out_file}")

def parse_trafego_file(infile):
    events = []
    with open(infile, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()

            if not line:
                continue
            m = LINE_RE.match(line)
            if not m:
                parts = line.split()
                if parts:
                    try:
                        ts = float(parts[0])
                        remainder = " ".join(parts[1:])
                    except:
                        continue
                else:
                    continue
            else:
                time_str = m.group(1)
                ts = None

                try:
                    parts = time_str.split(':')
                    horas = int(parts[0])
                    minutos = int(parts[1])
                    segundos = float(parts[2])
                    ts = (horas * 3600) + (minutos * 60) + segundos
                except (ValueError, IndexError):
                    try:
                        ts = float(time_str)
                    except ValueError:
                        pass

                if ts is None:
                    continue

                remainder = m.group(2)

            am = ADDR_RE.search(remainder)
            if not am:
                continue
            src = am.group("src")
            dst = am.group("dst")

            def split_ip_port(s):
                idx = s.rfind(".")
                if idx == -1:
                    return s, None
                ip = s[:idx]
                port = s[idx + 1:]
                try:
                    port_int = int(port)
                except:
                    port_int = None
                return ip, port_int

            src_ip, src_port = split_ip_port(src)
            dst_ip, dst_port = split_ip_port(dst)

            events.append({
                "ts": ts,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port
            })
    return events

def analyze_events(events, scan_threshold=10, window_seconds=60):
    results = {}
    total_by_ip = defaultdict(int)
    window_by_ip = defaultdict(deque)
    detected_by_ip = defaultdict(bool)

    events_sorted = sorted(events, key=lambda e: e["ts"])

    for e in events_sorted:
        src = e["src_ip"]
        ts = e["ts"]
        dst_port = e["dst_port"]
        total_by_ip[src] += 1

        dq = window_by_ip[src]
        dq.append((ts, dst_port))
        cutoff = ts - window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct_ports = {p for (_, p) in dq if p is not None}
        if len(distinct_ports) > scan_threshold:
            detected_by_ip[src] = True

    for ip, count in total_by_ip.items():
        results[ip] = {
            "total": count,
            "portscan": detected_by_ip[ip]
        }
    return results

def write_csv(results, out_csv):
    with open(out_csv, "w", newline='', encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["IP", "Total_Eventos", "Detectado_PortScan"])
        for ip, data in sorted(results.items(), key=lambda x: x[0]):
            writer.writerow([ip, data["total"], "Sim" if data["portscan"] else "Não"])
    print(f"[i] CSV escrito: {out_csv}")

def main():
    parser = argparse.ArgumentParser(description="Captura (opcional) e analisa tráfego IP, detecta port-scan.")
    parser.add_argument("--interface", "-i", help="Interface de rede (ex: eth0). Se omitido e --input fornecido, não captura.")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Segundos de captura (padrão 60).")
    parser.add_argument("--input", help="Arquivo de entrada trafego.txt (se fornecido, pula captura).")
    parser.add_argument("--trafego-out", default="trafego.txt", help="Arquivo onde será salvo o dump do tcpdump (padrão trafego.txt).")
    parser.add_argument("--output", default="relatorio.csv", help="Arquivo CSV de saída (padrão relatorio.csv).")
    parser.add_argument("--threshold", type=int, default=10, help="Número de portas distintas para considerar port-scan (padrão 10).")
    parser.add_argument("--window", type=int, default=60, help="Janela em segundos para deteção (padrão 60s).")
    args = parser.parse_args()

    if args.input:
        trafego_file = args.input
    else:
        if not args.interface:
            print("[ERRO] Interface não informada e nenhum arquivo de entrada fornecido.", file=sys.stderr)
            sys.exit(1)
        trafego_file = args.trafego_out
        try:
            run_capture(args.interface, args.duration, trafego_file)
        except Exception as ex:
            print(f"[ERRO] Falha na captura: {ex}", file=sys.stderr)
            sys.exit(2)

    print(f"[i] Analisando arquivo: {trafego_file}")
    events = parse_trafego_file(trafego_file)
    if not events:
        print("[aviso] Nenhum evento parseado do arquivo. Verifique se o formato do tcpdump é compatível (-nn -ttt ip).")
    results = analyze_events(events, scan_threshold=args.threshold, window_seconds=args.window)
    write_csv(results, args.output)
    print("[ok] Análise concluída.")

if __name__ == "__main__":
    main()
