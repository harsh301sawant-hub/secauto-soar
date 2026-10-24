import sqlite3
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(__file__), "soar.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Incidents table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE,
            attack_type TEXT,
            severity TEXT,
            source_ip TEXT,
            target_user TEXT,
            details TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Blocked IPs table (Automated response enforcement)
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Playbook Execution Logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS playbook_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            step_name TEXT,
            action_taken TEXT,
            result TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def log_incident(incident_id, attack_type, severity, source_ip, target_user, details):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT OR IGNORE INTO incidents (incident_id, attack_type, severity, source_ip, target_user, details, status)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
    ''', (incident_id, attack_type, severity, source_ip, target_user, details))
    conn.commit()
    conn.close()

def block_ip(ip, reason):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO blocked_ips (ip, reason)
        VALUES (?, ?)
    ''', (ip, reason))
    conn.commit()
    conn.close()

def is_ip_blocked(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT ip FROM blocked_ips WHERE ip = ?', (ip,))
    row = c.fetchone()
    conn.close()
    return row is not None

def record_playbook_step(incident_id, step_name, action_taken, result):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO playbook_logs (incident_id, step_name, action_taken, result)
        VALUES (?, ?, ?, ?)
    ''', (incident_id, step_name, action_taken, result))
    conn.commit()
    conn.close()

def get_recent_incidents(limit=20):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT ?', (limit,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_blocked_ips():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC')
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def update_incident_status(incident_id, status):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE incidents SET status = ? WHERE incident_id = ?', (status, incident_id))
    conn.commit()
    conn.close()
