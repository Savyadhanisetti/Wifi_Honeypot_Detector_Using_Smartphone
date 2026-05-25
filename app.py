from flask import Flask, render_template
import subprocess
import socket

app = Flask(__name__)

# -------------------------------
# GET LOCAL IP
# -------------------------------
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# -------------------------------
# WIFI SCAN (FIXED - NO DISCONNECT)
# -------------------------------
def scan_wifi():
    try:
        output = subprocess.check_output(
            "netsh wlan show networks mode=bssid",
            shell=True
        ).decode(errors="ignore")

        return output
    except:
        return ""

# -------------------------------
# PARSE WIFI
# -------------------------------
def parse_wifi(data):
    networks = []
    current_ssid = None
    current_security = "Unknown"

    lines = data.split("\n")

    for i in range(len(lines)):
        line = lines[i].strip()

        if line.startswith("SSID"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_ssid = parts[1].strip()

        if "Authentication" in line:
            current_security = line.split(":", 1)[1].strip()

        if "BSSID" in line:
            try:
                bssid = line.split(":", 1)[1].strip()

                signal = "0%"
                for j in range(i, min(i + 6, len(lines))):
                    if "Signal" in lines[j]:
                        signal = lines[j].split(":", 1)[1].strip()
                        break

                networks.append({
                    "ssid": current_ssid if current_ssid else "Hidden",
                    "bssid": bssid,
                    "signal": signal,
                    "security": current_security
                })

            except:
                continue

    return networks

# -------------------------------
# ANALYSIS
# -------------------------------
def analyze_network(n, all_networks):
    reasons = []

    if "open" in n["security"].lower():
        reasons.append("Open network")

    if any(x in n["ssid"].lower() for x in ["free", "wifi", "public"]):
        reasons.append("Suspicious name")

    same_ssid = [x for x in all_networks if x["ssid"] == n["ssid"]]
    if len(same_ssid) > 1:
        reasons.append("Multiple APs (Evil Twin)")

    return reasons

# -------------------------------
# RISK
# -------------------------------
def calculate_risk(reasons):
    if len(reasons) >= 3:
        return "High"
    elif len(reasons) == 2:
        return "Medium"
    else:
        return "Low"

# -------------------------------
# SUMMARY
# -------------------------------
def generate_summary(networks):
    summary = []
    ssid_map = {}

    for n in networks:
        ssid_map.setdefault(n["ssid"], []).append(n)

    for ssid, nets in ssid_map.items():
        reasons = []

        if len(nets) > 1:
            reasons.append("Multiple APs (Evil Twin)")

        if any("open" in n["security"].lower() for n in nets):
            reasons.append("Open Network")

        if any(x in ssid.lower() for x in ["free", "wifi"]):
            reasons.append("Suspicious Name")

        if reasons:
            summary.append({
                "ssid": ssid,
                "count": len(nets),
                "desc": " | ".join(reasons)
            })

    return summary

# -------------------------------
# MAIN
# -------------------------------
@app.route("/")
def home():
    raw = scan_wifi()
    nets = parse_wifi(raw)

    # Remove duplicates
    unique = {(n["ssid"], n["bssid"]): n for n in nets}
    nets = list(unique.values())

    # Demo
    nets.append({"ssid":"Free_Wifi","bssid":"AA:BB","signal":"90%","security":"Open"})
    nets.append({"ssid":"Free_Wifi","bssid":"CC:DD","signal":"85%","security":"WPA2"})

    summary = generate_summary(nets)

    return render_template(
        "index.html",
        nets=nets,
        summary=summary,
        analyze_network=analyze_network,
        calculate_risk=calculate_risk
    )

# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":
    ip = get_ip()
    print(f"\n📱 Open in mobile: http://{ip}:5000\n")

    app.run(host="0.0.0.0", port=5000, debug=False)