import sqlite3
import pandas as pd
import os
import random
from datetime import datetime, timedelta

print("=" * 60)
print("🛡️  QueryHunter AI - Database Setup")
print("=" * 60)

# Create data directory if not exists
os.makedirs('data', exist_ok=True)

# ============================================
# STEP 1: Generate Realistic Security Logs
# ============================================
print("\n[1/4] Generating synthetic security logs...")

def generate_security_logs(num_records=5000):
    """Generate realistic security log data"""
    
    attack_types = ['normal', 'probe', 'dos', 'r2l', 'u2r', 'brute_force']
    protocols = ['TCP', 'UDP', 'ICMP']
    actions = ['ALLOW', 'DENY', 'DROP', 'RESET']
    flags = ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3', 'OTH']
    services = ['http', 'https', 'ssh', 'dns', 'ftp', 'smtp', 'telnet', 'rdp', '-']
    
    # IP ranges
    internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
    external_ips = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(500)]
    dest_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    
    logs = []
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    
    for i in range(num_records):
        timestamp = base_time + timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        
        attack_type = random.choices(attack_types, weights=[50, 15, 15, 10, 5, 5])[0]
        
        if attack_type == 'normal':
            source_ip = random.choice(internal_ips)
            action = 'ALLOW'
        else:
            source_ip = random.choice(external_ips + internal_ips)
            action = random.choice(['DENY', 'DROP', 'RESET', 'ALLOW'])
        
        dest_ip = random.choice(dest_ips)
        protocol = random.choice(protocols)
        
        if attack_type == 'brute_force':
            port = 22
        elif attack_type == 'dos':
            port = random.choice([80, 443, 8080])
        else:
            port = random.choice([80, 443, 22, 53, 3389, 8080, 8443])
        
        if port == 80:
            service = 'http'
        elif port == 443:
            service = 'https'
        elif port == 22:
            service = 'ssh'
        elif port == 53:
            service = 'dns'
        else:
            service = random.choice(services)
        
        if attack_type == 'dos':
            bytes_count = random.randint(10000, 1000000)
        else:
            bytes_count = random.randint(64, 10000)
        
        duration = round(random.uniform(0.001, 3600), 3)
        flag = random.choice(flags)
        
        logs.append({
            'id': i + 1,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'port': port,
            'service': service,
            'action': action,
            'bytes': bytes_count,
            'duration': duration,
            'flag': flag,
            'attack_type': attack_type,
            'attack_label': 0 if attack_type == 'normal' else 1
        })
    
    return pd.DataFrame(logs)

df = generate_security_logs(5000)

db_path = 'data/security_logs.db'
conn = sqlite3.connect(db_path)
df.to_sql('logs', conn, if_exists='replace', index=False)
conn.close()

print(f"   ✅ Generated {len(df)} security log records")

# ============================================
# STEP 2: Show Dataset Summary
# ============================================
print("\n[2/4] Dataset Summary:")
print(f"   Total Records: {len(df)}")
print(f"   Date Range: {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"\n   Attack Type Distribution:")
for attack, count in df['attack_type'].value_counts().items():
    percentage = (count / len(df)) * 100
    bar = '█' * int(percentage / 2)
    print(f"   {attack:15} {count:5} ({percentage:5.1f}%) {bar}")

# ============================================
# STEP 3: Create AI Training Data Table
# ============================================
print("\n[3/4] Creating AI training tables...")

conn = sqlite3.connect(db_path)

conn.execute('''
CREATE TABLE IF NOT EXISTS training_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    query TEXT NOT NULL,
    explanation TEXT NOT NULL,
    attack_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS query_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    generated_query TEXT,
    results_count INTEGER,
    response_time_ms REAL,
    risk_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

sample_questions = [
    ("Show me all brute force attacks", "SELECT * FROM logs WHERE attack_type = 'brute_force'", "Filters logs to show only brute force attack attempts"),
    ("Find all denied SSH connections", "SELECT * FROM logs WHERE service = 'ssh' AND action = 'DENY'", "Finds SSH connections that were denied by the firewall"),
    ("What are the top 10 source IPs with most requests", "SELECT source_ip, COUNT(*) as count FROM logs GROUP BY source_ip ORDER BY count DESC LIMIT 10", "Lists the top 10 IP addresses that generated the most traffic"),
    ("Show me all DoS attacks", "SELECT * FROM logs WHERE attack_type = 'dos'", "Filters logs to show only Denial of Service attacks"),
    ("Find traffic from a specific IP 192.168.1.100", "SELECT * FROM logs WHERE source_ip = '192.168.1.100' OR dest_ip = '192.168.1.100'", "Shows all traffic involving the IP address 192.168.1.100"),
    ("Show me all normal traffic", "SELECT * FROM logs WHERE attack_type = 'normal'", "Filters logs to show only normal, non-malicious traffic"),
    ("Find all connections to port 80", "SELECT * FROM logs WHERE port = 80", "Shows all traffic targeting port 80 (HTTP)"),
    ("What attacks happened today", "SELECT * FROM logs WHERE attack_type != 'normal' AND date(timestamp) = date('now')", "Shows all attacks that occurred today"),
    ("Show me all dropped connections", "SELECT * FROM logs WHERE action = 'DROP'", "Filters logs to show all connections that were dropped"),
    ("Find probe attacks from external IPs", "SELECT * FROM logs WHERE attack_type = 'probe' AND source_ip LIKE '10.0.%'", "Shows probe attacks originating from external IP addresses"),
    ("Show me attacks with high bytes transfer", "SELECT * FROM logs WHERE bytes > 50000 ORDER BY bytes DESC", "Finds connections with unusually high data transfer"),
    ("Find UDP traffic", "SELECT * FROM logs WHERE protocol = 'UDP'", "Filters logs to show only UDP protocol traffic"),
    ("Show me all reset connections", "SELECT * FROM logs WHERE flag = 'RSTR'", "Shows all connections that were reset"),
    ("Find HTTP and HTTPS traffic", "SELECT * FROM logs WHERE service IN ('http', 'https')", "Filters logs to show only web traffic"),
    ("Show me attacks from yesterday", "SELECT * FROM logs WHERE attack_type != 'normal' AND date(timestamp) = date('now', '-1 day')", "Shows all attacks from the previous day"),
]

for question, query, explanation in sample_questions:
    conn.execute(
        'INSERT INTO training_data (question, query, explanation) VALUES (?, ?, ?)',
        (question, query, explanation)
    )

conn.commit()
conn.close()

print(f"   ✅ Added {len(sample_questions)} sample training questions")
print(f"   ✅ Created query_history table")

# ============================================
# STEP 4: Final Summary
# ============================================
print("\n[4/4] Setup Complete!")
print("\n" + "=" * 60)
print("🎉 Database ready!")
print("=" * 60)
print(f"\n📁 Database location: {os.path.abspath(db_path)}")
print(f"📊 Total records: {len(df)}")
print(f"🎯 Training samples: {len(sample_questions)}")
print("\n👉 Next step: Run 'python main.py' to start the backend server")
print("=" * 60)