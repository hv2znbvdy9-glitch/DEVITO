"""Run python server.py [--data-dir DIRECTORY] [--port 8765], then open localhost:8765.

Add complete, uniquely named CSVs by renaming them into DIRECTORY. Each refresh
includes new files. Headers: time_ms,soma_mV,apical_mV. Additional *_mV
columns become measurement positions. Times in the input are simulation times.
"""

import argparse
import csv
import hashlib
import io
import json
import math
import statistics
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit

HERE = Path(__file__).resolve().parent
EXPORT_NAME = "CSV-Stromstoß-DannyNicoHildebrand.sv"
METRICS = {
    "samples": "Messpunkte", "start_mV": "Start (mV)", "end_mV": "Ende (mV)",
    "min_mV": "Minimum (mV)", "min_ms": "Zeit Min. (ms)",
    "max_mV": "Maximum (mV)", "max_ms": "Zeit Max. (ms)",
    "mean_mV": "Mittelwert (mV)", "range_mV": "Spannweite (mV)",
    "std_mV": "Standardabw. (mV)", "duration_ms": "Dauer (ms)",
}
POSITIONS = {"soma_mV": "Soma", "apical_mV": "Apikaler Dendrit"}


def analyze(path):
    raw = path.read_bytes()
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
    fields = reader.fieldnames or []
    if len(fields) != len(set(fields)) or not {"time_ms", *POSITIONS}.issubset(fields):
        raise ValueError("CSV-Kopf prüfen")
    columns = {key: [] for key in fields if key.endswith("_mV")}
    times = []
    for row in reader:
        if None in row or None in row.values():
            raise ValueError(f"Spaltenzahl in Zeile {reader.line_num}")
        t = float(row["time_ms"])
        if not math.isfinite(t) or (times and t <= times[-1]):
            raise ValueError(f"Zeit in Zeile {reader.line_num}")
        times.append(t)
        for key, values in columns.items():
            v = float(row[key])
            if not math.isfinite(v):
                raise ValueError(f"Spannung in Zeile {reader.line_num}")
            values.append(v)
    if not times:
        raise ValueError("Keine Messpunkte")
    digest = hashlib.sha256(raw).hexdigest()
    rows = []
    for key, values in columns.items():
        low, high = min(values), max(values)
        rows.append(dict(source=path.name, position=POSITIONS.get(key, key[:-3]),
                         sha256=digest, samples=len(times), start_mV=values[0],
                         end_mV=values[-1], min_mV=low, min_ms=times[values.index(low)],
                         max_mV=high, max_ms=times[values.index(high)],
                         mean_mV=statistics.fmean(values), range_mV=high-low,
                         std_mV=statistics.pstdev(values), duration_ms=times[-1]-times[0]))
    return rows


def snapshot(directory):
    rows = json.loads((HERE / "reference.json").read_text(encoding="utf-8"))
    known = {(r["source"], r["sha256"]) for r in rows}
    errors = []
    for path in sorted(directory.glob("*.csv")):
        try:
            series = analyze(path)
            if (path.name, series[0]["sha256"]) not in known:
                rows.extend(series)
        except (ValueError, OSError, csv.Error, OverflowError) as exc:
            errors.append(f"{path.name}: {exc}")
    return dict(evaluated_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                rows=rows, errors=errors)


def systemverilog(data):
    # Constant data for simulation/testbenches. Index mapping is carried in strings.
    rows = data["rows"]
    lines = ["package hay_tables_pkg;", f"  localparam int N = {len(rows)};"]
    for key in ("source", "position", "sha256", *METRICS):
        kind = "real" if key in METRICS else "string"
        def literal(value):
            if kind == "real":
                return str(float(value))
            return '"' + ''.join(chr(b) if 32 <= b < 127 and b not in (34, 92)
                                 else chr(92) + format(b, "03o")
                                 for b in value.encode("utf-8")) + '"'
        values = ", ".join(literal(row[key]) for row in rows)
        lines.append(f"  localparam {kind} series_{key} [0:N-1] = '{{{values}}};")
    return "\n".join([*lines, "endpackage", ""])


def page(data):
    fields = {"source": "Quelldatei", "position": "Modellposition", **METRICS, "sha256": "SHA-256"}
    def cell(value):
        if isinstance(value, float):
            return f"{value:.3f}".replace(".", ",")
        return escape(str(value))
    body = "".join("<tr>" + "".join(f"<td>{cell(row[k])}</td>" for k in fields)
                   + "</tr>" for row in data["rows"])
    errors = "".join(f"<li>{escape(e)}</li>" for e in data["errors"])
    return ("<!doctype html><html lang='de'><meta charset=utf-8><title>" + EXPORT_NAME + "</title>"
            "<style>body{font:1rem system-ui;margin:2rem}table{border-collapse:collapse}"
            "th,td{padding:.5rem;border:1px solid #aaa;text-align:right}th{background:#def}</style>"
            "<h1>" + EXPORT_NAME + "</h1><p>Auswertung (UTC): " + data["evaluated_utc"]
            + " · <a href='/tables.json'>JSON</a> · <a href='/tables.sv'>SystemVerilog</a></p>"
            + "<table><thead><tr>" + "".join(f"<th>{v}</th>" for v in fields.values())
            + "</tr></thead><tbody>" + body + "</tbody></table>"
            + ("<h2>Übersprungene Dateien</h2><ul>" + errors + "</ul>" if errors else "") + "</html>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path.cwd())
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not args.data_dir.is_dir():
        parser.error("Datenverzeichnis fehlt")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = urlsplit(self.path).path
            if route not in ("/", "/tables.json", "/tables.sv"):
                self.send_error(404)
                return
            data = snapshot(args.data_dir)
            if route == "/tables.sv" and data["errors"]:
                self.send_error(422, "Invalid input CSV; see /tables.json")
                return
            if route == "/":
                mime, content = "text/html", page(data)
            elif route == "/tables.json":
                mime, content = "application/json", json.dumps(data, ensure_ascii=False, allow_nan=False)
            else:
                mime, content = "text/plain", systemverilog(data)
            payload = content.encode()
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            if route == "/tables.sv":
                self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(EXPORT_NAME))
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
