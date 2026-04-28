#!/usr/bin/env python3

import subprocess
import xml.etree.ElementTree as ET
import os
import datetime
import webbrowser   # Para abrir el HTML al final

# =========================
# BANNER (AZUL)
# =========================

def banner():
    BLUE = "\033[94m"
    RESET = "\033[0m"

    print(BLUE + r"""
 ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
 ██████╔╝██║   ██║██████╔╝   ██║   ███████║███████║██║ █╗ ██║█████╔╝ 
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██╔══██║██║███╗██║██╔═██╗ 
 ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝

        🦅 PortHawk - Scanner Inteligente
""" + RESET)

# =========================
# RIESGOS
# =========================

RISK_DB = {
    21: ("HIGH", "FTP inseguro"),
    22: ("LOW", "SSH"),
    23: ("CRITICAL", "Telnet sin cifrar"),
    80: ("MEDIUM", "HTTP sin cifrar"),
    443: ("LOW", "HTTPS"),
    445: ("HIGH", "SMB vulnerable"),
    3389: ("HIGH", "RDP vulnerable"),
    6379: ("CRITICAL", "Redis sin auth"),
    16992: ("HIGH", "Intel AMT acceso remoto"),
}

# =========================
# MENU
# =========================

def menu():
    print("\nSelecciona tipo de escaneo:\n")
    print("1. Rápido (descubrimiento básico)")
    print("2. Balanceado (servicios y versiones)")
    print("3. Completo (masscan + nmap profundo con SO)")
    print("0. Salir\n")

# =========================
# SCANNER
# =========================

def run_scan(target, option):
    if option == "1":
        cmd = ["nmap", "-F", "-oX", "-", target]
    elif option == "2":
        cmd = ["nmap", "-sV", "-T4", "-oX", "-", target]
    elif option == "3":
        # Escaneo profundo: versiones, scripts, detección de SO, top 1000 puertos
        cmd = ["nmap", "-sV", "-sC", "-O", "--top-ports", "1000", "-T4", "-oX", "-", target]
    else:
        print("Opción inválida")
        return ""

    print("\n🔍 Ejecutando escaneo...\n")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"⚠️  Nmap terminó con errores:\n{result.stderr}")
        return ""
    return result.stdout

# =========================
# PARSER XML → PYTHON
# =========================

def parse(xml):
    results = []
    root = ET.fromstring(xml)

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue

        ip = addr.get("addr")
        ports_data = []

        # --- Parsear puertos ---
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = int(port.get("portid"))
            service_el = port.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            risk, desc = RISK_DB.get(port_id, ("INFO", "Sin info"))

            ports_data.append({
                "port": port_id,
                "service": service,
                "version": f"{product} {version}".strip(),
                "risk": risk,
                "desc": desc
            })

        # --- Parsear sistema operativo ---
        os_matches = []
        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                name = osmatch.get("name")
                accuracy = osmatch.get("accuracy")
                if name:
                    os_matches.append({
                        "name": name,
                        "accuracy": accuracy
                    })

        results.append({
            "ip": ip,
            "ports": ports_data,
            "os": os_matches   # lista de SO detectados
        })

    return results

# =========================
# REPORTES (TXT + HTML)
# =========================

def save_report(data, target):
    os.makedirs("reportes", exist_ok=True)

    clean = target.replace("/", "_").replace(".", "_")
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"reporte_{clean}_{timestamp}"

    # ---- Reporte TXT ----
    txt_path = f"reportes/{base_filename}.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(" PORTHAWK REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Fecha: {datetime.datetime.now()}\n\n")

        for host in data:
            f.write(f"\n HOST: {host['ip']}\n")
            # Sistema operativo
            if host["os"]:
                for osm in host["os"]:
                    acc = f" ({osm['accuracy']}%)" if osm['accuracy'] else ""
                    f.write(f"     SO detectado: {osm['name']}{acc}\n")
            f.write("-" * 40 + "\n")
            if not host["ports"]:
                f.write("  Sin puertos abiertos\n")
                continue
            for p in host["ports"]:
                f.write(f"\n   Puerto {p['port']}\n")
                f.write(f"     Servicio: {p['service']}\n")
                if p["version"]:
                    f.write(f"     Versión: {p['version']}\n")
                f.write(f"     Riesgo: {p['risk']} - {p['desc']}\n")

    # ---- Reporte HTML ----
    html_path = f"reportes/{base_filename}.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html(data, target))

    print(f"\n📁 Reporte TXT  : {txt_path}")
    print(f"🌐 Reporte HTML : {html_path}")

    # Abrir automáticamente el HTML en el navegador
    webbrowser.open(f"file://{os.path.abspath(html_path)}")

def generate_html(data, target):
    risk_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "INFO": "#17a2b8"
    }

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>PortHawk Report - {target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f8f9fa;
            color: #212529;
        }}
        .container {{
            max-width: 1000px;
            margin: auto;
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #0d6efd;
            border-bottom: 2px solid #0d6efd;
            padding-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 20px;
        }}
        .host {{
            margin-top: 30px;
        }}
        .host h2 {{
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 8px;
        }}
        .os-info {{
            background: #e2e3e5;
            padding: 5px 10px;
            border-radius: 6px;
            margin: 5px 0 10px;
            display: inline-block;
            font-size: 0.9em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        th {{
            background-color: #f1f3f5;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            color: white;
            font-size: 0.85em;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #6c757d;
            font-size: 0.85em;
        }}
        .no-ports {{
            font-style: italic;
            color: #6c757d;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 PortHawk Report</h1>
        <div class="meta">
            <strong>Objetivo:</strong> {target}<br>
            <strong>Fecha:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
"""
    for host in data:
        html += f'<div class="host"><h2> {host["ip"]}</h2>\n'
        # Mostrar SO si hay
        if host["os"]:
            for osm in host["os"]:
                acc_str = f' ({osm["accuracy"]}%)' if osm["accuracy"] else ''
                html += f'<div class="os-info"> SO detectado: <strong>{osm["name"]}{acc_str}</strong></div>\n'
        if not host["ports"]:
            html += '<p class="no-ports">Sin puertos abiertos</p></div>\n'
            continue

        html += """<table>
            <thead>
                <tr>
                    <th>Puerto</th>
                    <th>Servicio</th>
                    <th>Versión</th>
                    <th>Riesgo</th>
                </tr>
            </thead>
            <tbody>
"""
        for p in host["ports"]:
            color = risk_colors.get(p["risk"], "#6c757d")
            version = p["version"] if p["version"] else "-"
            html += f"""<tr>
                <td>{p['port']}</td>
                <td>{p['service']}</td>
                <td>{version}</td>
                <td><span class="badge" style="background-color:{color};">{p['risk']} - {p['desc']}</span></td>
            </tr>
"""
        html += "</tbody></table></div>\n"

    html += """<div class="footer">Generado por PortHawk</div>
    </div>
</body>
</html>"""
    return html

# =========================
# MAIN
# =========================

def main():
    banner()
    target = input(" Target: ").strip()
    if not target:
        print("Debes especificar un objetivo.")
        return

    while True:
        menu()
        option = input("Opción: ").strip()

        if option == "0":
            break

        xml_output = run_scan(target, option)
        if not xml_output:
            continue

        try:
            data = parse(xml_output)
        except Exception as e:
            print("❌ Error parseando XML:", e)
            continue

        save_report(data, target)
        print("\n✅ Escaneo finalizado\n")

if __name__ == "__main__":
    main()