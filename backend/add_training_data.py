"""
Add Training Data for QueryHunter AI
Populates the training_data table with diverse question-query pairs
Improves RAG accuracy by providing more examples
"""

import sqlite3
import os

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "security_logs.db")


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    return conn


def add_training_data():
    """Add comprehensive training data"""
    
    training_data = [
        # ============================================
        # Attack Type Queries (15 questions)
        # ============================================
        ("Show me all brute force attacks", 
         "SELECT * FROM logs WHERE attack_type = 'brute_force' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only brute force attack attempts"),
        
        ("Find all DoS attacks", 
         "SELECT * FROM logs WHERE attack_type = 'dos' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only Denial of Service attacks"),
        
        ("What probe attacks happened?", 
         "SELECT * FROM logs WHERE attack_type = 'probe' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only probe/scanning attacks"),
        
        ("Show me all R2L attacks", 
         "SELECT * FROM logs WHERE attack_type = 'r2l' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only Remote to Local attacks"),
        
        ("Find U2R attacks", 
         "SELECT * FROM logs WHERE attack_type = 'u2r' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only User to Root attacks"),
        
        ("Show me all normal traffic", 
         "SELECT * FROM logs WHERE attack_type = 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only normal, non-malicious traffic"),
        
        ("What attacks happened today?", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND date(timestamp) = date('now') ORDER BY timestamp DESC LIMIT 100",
         "Shows all attacks that occurred today"),
        
        ("Show me all attacks from yesterday", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND date(timestamp) = date('now', '-1 day') ORDER BY timestamp DESC LIMIT 100",
         "Shows all attacks from yesterday"),
        
        ("Find all attacks from this week", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND timestamp >= datetime('now', '-7 days') ORDER BY timestamp DESC LIMIT 100",
         "Shows all attacks from the past 7 days"),
        
        ("What are the most common attack types?", 
         "SELECT attack_type, COUNT(*) as count FROM logs WHERE attack_type != 'normal' GROUP BY attack_type ORDER BY count DESC",
         "Lists attack types by frequency"),
        
        ("Show me attacks with high bytes transfer", 
         "SELECT * FROM logs WHERE bytes > 50000 ORDER BY bytes DESC LIMIT 100",
         "Finds connections with unusually high data transfer"),
        
        ("Find attacks with long duration", 
         "SELECT * FROM logs WHERE duration > 300 AND attack_type != 'normal' ORDER BY duration DESC LIMIT 100",
         "Shows attacks with connections lasting more than 5 minutes"),
        
        ("Show me all attacks that were allowed", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND action = 'ALLOW' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks that were allowed by the firewall"),
        
        ("Find attacks that were blocked", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND action IN ('DENY', 'DROP') ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks that were blocked by the firewall"),
        
        ("What percentage of traffic is attacks?", 
         "SELECT ROUND(COUNT(CASE WHEN attack_type != 'normal' THEN 1 END) * 100.0 / COUNT(*), 2) as attack_percentage FROM logs",
         "Calculates the percentage of traffic that is attacks"),
        
        # ============================================
        # Service/Port Queries (15 questions)
        # ============================================
        ("Find all denied SSH connections", 
         "SELECT * FROM logs WHERE service = 'ssh' AND action = 'DENY' ORDER BY timestamp DESC LIMIT 100",
         "Finds SSH connections that were denied by the firewall"),
        
        ("Show me all connections to port 80", 
         "SELECT * FROM logs WHERE port = 80 ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic targeting port 80 (HTTP)"),
        
        ("Find all connections to port 443", 
         "SELECT * FROM logs WHERE port = 443 ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic targeting port 443 (HTTPS)"),
        
        ("Show me all SSH traffic", 
         "SELECT * FROM logs WHERE service = 'ssh' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only SSH traffic"),
        
        ("Find HTTP traffic", 
         "SELECT * FROM logs WHERE service = 'http' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only HTTP traffic"),
        
        ("Show me HTTPS traffic", 
         "SELECT * FROM logs WHERE service = 'https' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only HTTPS traffic"),
        
        ("Find DNS queries", 
         "SELECT * FROM logs WHERE service = 'dns' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only DNS traffic"),
        
        ("Show me FTP connections", 
         "SELECT * FROM logs WHERE service = 'ftp' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only FTP traffic"),
        
        ("Find RDP connections", 
         "SELECT * FROM logs WHERE service = 'rdp' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only Remote Desktop connections"),
        
        ("Show me all connections to port 22", 
         "SELECT * FROM logs WHERE port = 22 ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic targeting port 22 (SSH)"),
        
        ("Find HTTP and HTTPS traffic", 
         "SELECT * FROM logs WHERE service IN ('http', 'https') ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only web traffic"),
        
        ("Show me attacks on SSH", 
         "SELECT * FROM logs WHERE service = 'ssh' AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks targeting SSH service"),
        
        ("Find attacks on web services", 
         "SELECT * FROM logs WHERE service IN ('http', 'https') AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks targeting web services"),
        
        ("What are the most targeted ports?", 
         "SELECT port, service, COUNT(*) as count FROM logs WHERE attack_type != 'normal' GROUP BY port ORDER BY count DESC LIMIT 10",
         "Lists the most frequently targeted ports"),
        
        ("Show me traffic on port 3389", 
         "SELECT * FROM logs WHERE port = 3389 ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic targeting port 3389 (RDP)"),
        
        # ============================================
        # IP Address Queries (10 questions)
        # ============================================
        ("Find traffic from IP 192.168.1.100", 
         "SELECT * FROM logs WHERE source_ip = '192.168.1.100' OR dest_ip = '192.168.1.100' ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic involving the IP address 192.168.1.100"),
        
        ("Show me traffic to 192.168.1.50", 
         "SELECT * FROM logs WHERE dest_ip = '192.168.1.50' ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic destined for IP 192.168.1.50"),
        
        ("What are the top 10 source IPs?", 
         "SELECT source_ip, COUNT(*) as count FROM logs GROUP BY source_ip ORDER BY count DESC LIMIT 10",
         "Lists the top 10 IP addresses that generated the most traffic"),
        
        ("Find top 10 destination IPs", 
         "SELECT dest_ip, COUNT(*) as count FROM logs GROUP BY dest_ip ORDER BY count DESC LIMIT 10",
         "Lists the top 10 most targeted IP addresses"),
        
        ("Show me attacks from external IPs", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND source_ip LIKE '10.0.%' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks originating from external IP addresses"),
        
        ("Find traffic from internal network", 
         "SELECT * FROM logs WHERE source_ip LIKE '192.168.%' ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic originating from the internal network"),
        
        ("Show me IPs with most attacks", 
         "SELECT source_ip, COUNT(*) as attack_count FROM logs WHERE attack_type != 'normal' GROUP BY source_ip ORDER BY attack_count DESC LIMIT 10",
         "Lists the top 10 IP addresses that generated the most attacks"),
        
        ("Find IPs that were attacked the most", 
         "SELECT dest_ip, COUNT(*) as attack_count FROM logs WHERE attack_type != 'normal' GROUP BY dest_ip ORDER BY attack_count DESC LIMIT 10",
         "Lists the top 10 IP addresses that were targeted the most"),
        
        ("Show me traffic between two IPs", 
         "SELECT * FROM logs WHERE (source_ip = '192.168.1.10' AND dest_ip = '192.168.1.20') OR (source_ip = '192.168.1.20' AND dest_ip = '192.168.1.10') ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic between two specific IP addresses"),
        
        ("Find IPs with brute force attacks", 
         "SELECT DISTINCT source_ip FROM logs WHERE attack_type = 'brute_force' ORDER BY source_ip",
         "Lists all IP addresses that attempted brute force attacks"),
        
        # ============================================
        # Protocol Queries (8 questions)
        # ============================================
        ("Show me all TCP traffic", 
         "SELECT * FROM logs WHERE protocol = 'TCP' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only TCP protocol traffic"),
        
        ("Find UDP traffic", 
         "SELECT * FROM logs WHERE protocol = 'UDP' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only UDP protocol traffic"),
        
        ("Show me ICMP traffic", 
         "SELECT * FROM logs WHERE protocol = 'ICMP' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show only ICMP protocol traffic"),
        
        ("Find TCP attacks", 
         "SELECT * FROM logs WHERE protocol = 'TCP' AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks using TCP protocol"),
        
        ("Show me UDP attacks", 
         "SELECT * FROM logs WHERE protocol = 'UDP' AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks using UDP protocol"),
        
        ("What is the protocol distribution?", 
         "SELECT protocol, COUNT(*) as count FROM logs GROUP BY protocol ORDER BY count DESC",
         "Shows the distribution of protocols in the logs"),
        
        ("Find attacks by protocol", 
         "SELECT protocol, COUNT(*) as attack_count FROM logs WHERE attack_type != 'normal' GROUP BY protocol ORDER BY attack_count DESC",
         "Shows attack count by protocol"),
        
        ("Show me ICMP attacks", 
         "SELECT * FROM logs WHERE protocol = 'ICMP' AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks using ICMP protocol"),
        
        # ============================================
        # Action Queries (8 questions)
        # ============================================
        ("Show me all dropped connections", 
         "SELECT * FROM logs WHERE action = 'DROP' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show all connections that were dropped"),
        
        ("Find all denied connections", 
         "SELECT * FROM logs WHERE action = 'DENY' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show all connections that were denied"),
        
        ("Show me allowed connections", 
         "SELECT * FROM logs WHERE action = 'ALLOW' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show all connections that were allowed"),
        
        ("Find reset connections", 
         "SELECT * FROM logs WHERE action = 'RESET' ORDER BY timestamp DESC LIMIT 100",
         "Filters logs to show all connections that were reset"),
        
        ("What is the action distribution?", 
         "SELECT action, COUNT(*) as count FROM logs GROUP BY action ORDER BY count DESC",
         "Shows the distribution of firewall actions"),
        
        ("Show me attacks that were dropped", 
         "SELECT * FROM logs WHERE action = 'DROP' AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks that were dropped by the firewall"),
        
        ("Find attacks that were denied", 
         "SELECT * FROM logs WHERE action = 'DENY' AND attack_type != 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks that were denied by the firewall"),
        
        ("Show me normal traffic that was denied", 
         "SELECT * FROM logs WHERE action = 'DENY' AND attack_type = 'normal' ORDER BY timestamp DESC LIMIT 100",
         "Shows normal traffic that was denied by the firewall"),
        
        # ============================================
        # Time-Based Queries (8 questions)
        # ============================================
        ("Show me traffic from the last hour", 
         "SELECT * FROM logs WHERE timestamp >= datetime('now', '-1 hour') ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic from the last hour"),
        
        ("Find traffic from the last 24 hours", 
         "SELECT * FROM logs WHERE timestamp >= datetime('now', '-24 hours') ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic from the last 24 hours"),
        
        ("Show me traffic from this week", 
         "SELECT * FROM logs WHERE timestamp >= datetime('now', '-7 days') ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic from the past 7 days"),
        
        ("Find traffic from this month", 
         "SELECT * FROM logs WHERE timestamp >= datetime('now', '-30 days') ORDER BY timestamp DESC LIMIT 100",
         "Shows all traffic from the past 30 days"),
        
        ("What is the hourly traffic pattern?", 
         "SELECT strftime('%H', timestamp) as hour, COUNT(*) as count FROM logs GROUP BY hour ORDER BY hour",
         "Shows traffic distribution by hour of day"),
        
        ("Show me daily traffic trend", 
         "SELECT date(timestamp) as date, COUNT(*) as count FROM logs GROUP BY date(timestamp) ORDER BY date",
         "Shows daily traffic trend"),
        
        ("Find peak traffic hours", 
         "SELECT strftime('%H', timestamp) as hour, COUNT(*) as count FROM logs GROUP BY hour ORDER BY count DESC LIMIT 5",
         "Shows the top 5 peak traffic hours"),
        
        ("Show me attacks by hour", 
         "SELECT strftime('%H', timestamp) as hour, COUNT(*) as attack_count FROM logs WHERE attack_type != 'normal' GROUP BY hour ORDER BY attack_count DESC",
         "Shows attack distribution by hour"),
        
        # ============================================
        # Complex Queries (10 questions)
        # ============================================
        ("Find brute force attacks on SSH from yesterday", 
         "SELECT * FROM logs WHERE attack_type = 'brute_force' AND service = 'ssh' AND date(timestamp) = date('now', '-1 day') ORDER BY timestamp DESC LIMIT 100",
         "Shows brute force attacks on SSH from yesterday"),
        
        ("Show me DoS attacks that were blocked", 
         "SELECT * FROM logs WHERE attack_type = 'dos' AND action IN ('DENY', 'DROP') ORDER BY timestamp DESC LIMIT 100",
         "Shows DoS attacks that were blocked by the firewall"),
        
        ("Find high bytes transfer from external IPs", 
         "SELECT * FROM logs WHERE bytes > 50000 AND source_ip LIKE '10.0.%' ORDER BY bytes DESC LIMIT 100",
         "Shows high data transfer from external IPs"),
        
        ("Show me attacks on port 80 with high bytes", 
         "SELECT * FROM logs WHERE port = 80 AND attack_type != 'normal' AND bytes > 10000 ORDER BY bytes DESC LIMIT 100",
         "Shows attacks on port 80 with high data transfer"),
        
        ("Find probe attacks from external IPs", 
         "SELECT * FROM logs WHERE attack_type = 'probe' AND source_ip LIKE '10.0.%' ORDER BY timestamp DESC LIMIT 100",
         "Shows probe attacks originating from external IP addresses"),
        
        ("Show me attacks with reset connections", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND flag LIKE 'RST%' ORDER BY timestamp DESC LIMIT 100",
         "Shows attacks with reset connection flags"),
        
        ("Find UDP attacks that were allowed", 
         "SELECT * FROM logs WHERE protocol = 'UDP' AND attack_type != 'normal' AND action = 'ALLOW' ORDER BY timestamp DESC LIMIT 100",
         "Shows UDP attacks that were allowed by the firewall"),
        
        ("Show me long duration attacks on web", 
         "SELECT * FROM logs WHERE attack_type != 'normal' AND service IN ('http', 'https') AND duration > 60 ORDER BY duration DESC LIMIT 100",
         "Shows attacks on web services with long connection duration"),
        
        ("Find attacks from IPs that hit multiple ports", 
         "SELECT source_ip, COUNT(DISTINCT port) as ports_hit FROM logs WHERE attack_type != 'normal' GROUP BY source_ip HAVING ports_hit > 5 ORDER BY ports_hit DESC LIMIT 10",
         "Shows IPs that attacked multiple ports (potential scanning)"),
        
        ("Show me the most active attackers", 
         "SELECT source_ip, COUNT(*) as attack_count, COUNT(DISTINCT attack_type) as attack_types FROM logs WHERE attack_type != 'normal' GROUP BY source_ip ORDER BY attack_count DESC LIMIT 10",
         "Shows the most active attacking IP addresses"),
    ]
    
    conn = get_db_connection()
    
    # Check current count
    current_count = conn.execute("SELECT COUNT(*) FROM training_data").fetchone()[0]
    print(f"Current training data count: {current_count}")
    
    # Insert new training data
    added_count = 0
    for question, query, explanation in training_data:
        # Check if question already exists
        existing = conn.execute(
            "SELECT id FROM training_data WHERE question = ?", 
            (question,)
        ).fetchone()
        
        if not existing:
            conn.execute(
                "INSERT INTO training_data (question, query, explanation) VALUES (?, ?, ?)",
                (question, query, explanation)
            )
            added_count += 1
    
    conn.commit()
    
    # Get new count
    new_count = conn.execute("SELECT COUNT(*) FROM training_data").fetchone()[0]
    conn.close()
    
    print(f"✅ Added {added_count} new training questions")
    print(f"📊 Total training data: {new_count} questions")
    print(f"\nBreakdown by category:")
    print(f"  - Attack Type Queries: 15")
    print(f"  - Service/Port Queries: 15")
    print(f"  - IP Address Queries: 10")
    print(f"  - Protocol Queries: 8")
    print(f"  - Action Queries: 8")
    print(f"  - Time-Based Queries: 8")
    print(f"  - Complex Queries: 10")
    print(f"  - Original Questions: {current_count}")
    print(f"\n🎯 Total: {new_count} training questions")


if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  QueryHunter AI - Add Training Data")
    print("=" * 60)
    print()
    
    add_training_data()
    
    print("\n" + "=" * 60)
    print("✅ Training data added successfully!")
    print("=" * 60)