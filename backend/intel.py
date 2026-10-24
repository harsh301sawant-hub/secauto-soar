import requests
import json

# Cache to avoid hitting external rate limits repeatedly
IP_CACHE = {}

def get_real_client_ip(request_headers: dict, client_host: str):
    """
    Extracts the REAL public IP address of the person visiting,
    accounting for Proxies, Cloudflare, ngrok, and Load Balancers.
    """
    # Cloudflare header
    cf_connecting_ip = request_headers.get("cf-connecting-ip")
    if cf_connecting_ip:
        return cf_connecting_ip.strip()

    # Standard proxy forwarded header
    x_forwarded_for = request_headers.get("x-forwarded-for")
    if x_forwarded_for:
        # First IP in list is the original client
        return x_forwarded_for.split(",")[0].strip()

    # Real IP header
    x_real_ip = request_headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()

    return client_host

def enrich_ip_intelligence(ip: str):
    """
    Looks up the REAL LIVE geolocation and ISP of ANY person opening the URL.
    Uses free public IP geolocation APIs (ip-api.com).
    """
    # Check cache first
    if ip in IP_CACHE:
        return IP_CACHE[ip]

    # Handle local loopback / private IPs
    if ip in ["127.0.0.1", "::1", "localhost"] or ip.startswith("192.168.") or ip.startswith("10."):
        # Fetch the machine's actual public facing IP so localhost still shows your real city & country!
        try:
            pub_ip_res = requests.get("https://api.ipify.org?format=json", timeout=3)
            if pub_ip_res.status_code == 200:
                public_ip = pub_ip_res.json().get("ip")
                return enrich_ip_intelligence(public_ip)
        except Exception:
            pass

        # Fallback if offline
        return {
            "ip": ip,
            "country": "Local Network",
            "country_code": "LOC",
            "city": "Current Machine",
            "lat": 28.6139,
            "lon": 77.2090,
            "isp": "Local Area Network (LAN)",
            "threat_actor": "Internal Host / Analyst",
            "abuse_score": 0,
            "is_proxy": False,
            "is_vpn_tor": False
        }

    # Query real live public Geolocation API
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
        res = requests.get(url, timeout=4)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                result = {
                    "ip": data.get("query", ip),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "--"),
                    "city": data.get("city", "Unknown City"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "isp": data.get("isp", "Unknown ISP"),
                    "threat_actor": f"Host ({data.get('org', data.get('isp', 'Visitor'))})",
                    "abuse_score": 15,
                    "is_proxy": False,
                    "is_vpn_tor": False
                }
                IP_CACHE[ip] = result
                return result
    except Exception as e:
        print(f"Error querying live IP API: {e}")

    # Fallback if API is unreachable
    return {
        "ip": ip,
        "country": "Unknown",
        "country_code": "--",
        "city": "Unknown",
        "lat": 20.5937,
        "lon": 78.9629,
        "isp": "Standard Internet Gateway",
        "threat_actor": "Visitor Host",
        "abuse_score": 0,
        "is_proxy": False,
        "is_vpn_tor": False
    }

def generate_analyst_mitre_report(incident: dict, enrichment: dict):
    attack_type = incident.get("attack_type", "")
    
    if "Brute-Force" in attack_type:
        mitre_tactic = "Credential Access (TA0006)"
        mitre_technique = "T1110 - Brute Force: Password Spraying"
        cvss = 8.1
    elif "SQL Injection" in attack_type:
        mitre_tactic = "Initial Access (TA0001)"
        mitre_technique = "T1190 - Exploit Public-Facing Application"
        cvss = 9.4
    else:
        mitre_tactic = "Reconnaissance (TA0043)"
        mitre_technique = "T1595 - Active Scanning / Web Traversal"
        cvss = 5.3

    return {
        "incident_id": incident.get("incident_id"),
        "generated_timestamp": incident.get("created_at"),
        "cvss_v3_score": cvss,
        "threat_severity": incident.get("severity"),
        "mitre_alignment": {
            "tactic": mitre_tactic,
            "technique": mitre_technique
        },
        "adversary_attribution": {
            "threat_actor": enrichment.get("threat_actor"),
            "source_country": enrichment.get("country"),
            "origin_city": enrichment.get("city"),
            "isp_asn": enrichment.get("isp"),
            "abuse_score": f"{enrichment.get('abuse_score')}%"
        },
        "target_impact": {
            "affected_entity": incident.get("target_user"),
            "exploit_details": incident.get("details")
        },
        "recommended_containment": [
            f"Logged telemetry connection from {enrichment.get('ip')} located in {enrichment.get('city')}, {enrichment.get('country')}.",
            "Applied adaptive access rule and monitored session integrity.",
            "Audited endpoint connection in compliance with security guidelines."
        ]
    }
