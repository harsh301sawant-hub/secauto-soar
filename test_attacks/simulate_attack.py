"""
SecAuto SOAR - Attack Simulation Script for 150-Mark Viva Presentation
Run this script in a separate terminal during your evaluation to demonstrate live attack mitigation.
"""
import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def print_banner():
    print("=" * 60)
    print("  SECAUTO SOAR - LIVE ATTACK SIMULATION HARNESS")
    print("=" * 60)

def test_brute_force():
    print("\n[+] Triggering Brute-Force Credential Stuffing Attack...")
    target_ip = "185.220.101.5"
    username = "ciso@target-enterprise.com"

    for i in range(1, 6):
        payload = {
            "ip": target_ip,
            "username": username,
            "password": f"cracked_pass_{i}"
        }
        print(f" -> Attempt #{i}: Sending invalid credentials from {target_ip}...")
        try:
            res = requests.post(f"{BASE_URL}/api/simulate/login", json=payload)
            data = res.json()
            if data.get("status") == "ATTACK_TRIGGERED":
                print(f"\n[!] SUCCESS: Threat triggered! Incident ID: {data.get('incident_id')}")
                print(f"    Message: {data.get('message')}")
                break
            elif data.get("status") == "BLOCKED":
                print(f"\n[🛡️] ATTACK REJECTED: Attacker IP is already quarantined/blocked!")
                break
        except Exception as e:
            print(f"[x] Error reaching server: {e}")
            return
        time.sleep(0.5)

def test_sqli():
    print("\n[+] Injecting Web Exploitation (SQL Injection) Payload...")
    payload = {
        "ip": "45.142.212.88",
        "path": "/api/users/profile",
        "payload": "' UNION SELECT username, password_hash FROM admin_users --"
    }
    try:
        res = requests.post(f"{BASE_URL}/api/simulate/web-attack", json=payload)
        data = res.json()
        print(f"[!] Server Response: {data}")
    except Exception as e:
        print(f"[x] Error: {e}")

def test_phishing():
    print("\n[+] Scanning Suspicious Phishing URL...")
    target_url = "https://secure-login-paypal.verify-account.cc/billing-resolve"
    try:
        res = requests.post(f"{BASE_URL}/api/scan/phishing", json={"url": target_url})
        data = res.json()
        print(f" -> URL: {data['url']}")
        print(f" -> Threat Verdict: {data['verdict']}")
        print(f" -> Risk Score: {data['risk_score']}/100")
        print(f" -> Detected Flaws:")
        for r in data['reasons']:
            print(f"    - {r}")
    except Exception as e:
        print(f"[x] Error: {e}")

if __name__ == "__main__":
    print_banner()
    print("Select Attack Vector to Test:")
    print("1. Brute-Force Password Spraying Attack")
    print("2. Web SQL Injection Payload Attack")
    print("3. Phishing Link Deception Scan")
    print("4. Run Full Demonstration Suite")
    
    choice = input("\nEnter choice [1-4]: ").strip()
    if choice == "1":
        test_brute_force()
    elif choice == "2":
        test_sqli()
    elif choice == "3":
        test_phishing()
    elif choice == "4":
        test_brute_force()
        time.sleep(1)
        test_sqli()
        time.sleep(1)
        test_phishing()
    else:
        print("Invalid choice.")
