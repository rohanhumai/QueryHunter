"""
AI Query Engine for QueryHunter AI
Translates natural language questions to SQL queries
"""

import re
import sqlite3
import pandas as pd
import os
import sys
from typing import Tuple, List, Dict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Get the absolute path to the database
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_logs.db")


# Keyword mappings for query translation
ATTACK_TYPES = {
    'brute force': ['brute force', 'bruteforce', 'brute-force', 'password attack', 'credential stuffing'],
    'dos': ['dos', 'denial of service', 'ddos', 'distributed denial'],
    'probe': ['probe', 'scanning', 'scan', 'reconnaissance', 'sweep'],
    'r2l': ['r2l', 'remote to local', 'unauthorized access'],
    'u2r': ['u2r', 'user to root', 'privilege escalation', 'root access'],
    'normal': ['normal', 'benign', 'legitimate', 'safe']
}

PROTOCOLS = {
    'tcp': ['tcp', 'transmission control protocol'],
    'udp': ['udp', 'user datagram protocol'],
    'icmp': ['icmp', 'ping', 'echo request']
}

SERVICES = {
    'http': ['http', 'web', 'port 80', 'website'],
    'https': ['https', 'ssl', 'tls', 'secure web', 'port 443'],
    'ssh': ['ssh', 'secure shell', 'port 22', 'remote login'],
    'dns': ['dns', 'domain name', 'port 53', 'name resolution'],
    'ftp': ['ftp', 'file transfer', 'port 21'],
    'smtp': ['smtp', 'email', 'mail', 'port 25'],
    'telnet': ['telnet', 'port 23'],
    'rdp': ['rdp', 'remote desktop', 'port 3389']
}

ACTIONS = {
    'ALLOW': ['allow', 'allowed', 'permit', 'permitted', 'accept', 'accepted'],
    'DENY': ['deny', 'denied', 'block', 'blocked', 'reject', 'rejected'],
    'DROP': ['drop', 'dropped', 'discard', 'discarded'],
    'RESET': ['reset', 'rst', 'connection reset']
}


def get_db_connection():
    """Get database connection"""
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found at: {DB_PATH}. Run setup_database.py first.")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def translate_question_to_sql(question: str) -> Tuple[str, List[str], Dict]:
    """Translate natural language question to SQL query"""
    question_lower = question.lower().strip()
    
    sql_parts = ["SELECT * FROM logs WHERE 1=1"]
    explanation_parts = []
    metadata = {
        "attack_types_found": [],
        "services_found": [],
        "protocols_found": [],
        "actions_found": [],
        "ips_found": [],
        "time_filters": [],
        "custom_filters": []
    }
    
    # 1. Detect Attack Types
    for attack_type, keywords in ATTACK_TYPES.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"attack_type = '{attack_type}'")
            explanation_parts.append(f"filtered for {attack_type} traffic")
            metadata["attack_types_found"].append(attack_type)
    
    # 2. Detect Services
    for service, keywords in SERVICES.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"service = '{service}'")
            explanation_parts.append(f"filtered for {service.upper()} service")
            metadata["services_found"].append(service)
    
    # 3. Detect Protocols
    for protocol, keywords in PROTOCOLS.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"protocol = '{protocol}'")
            explanation_parts.append(f"filtered for {protocol.upper()} protocol")
            metadata["protocols_found"].append(protocol)
    
    # 4. Detect Actions
    for action, keywords in ACTIONS.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"action = '{action}'")
            explanation_parts.append(f"showing only {action} actions")
            metadata["actions_found"].append(action)
    
    # 5. Detect IP Addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips_found = re.findall(ip_pattern, question)
    for ip in ips_found:
        sql_parts.append(f"(source_ip = '{ip}' OR dest_ip = '{ip}')")
        explanation_parts.append(f"filtered for IP address {ip}")
        metadata["ips_found"].append(ip)
    
    # 6. Detect Port Numbers
    port_pattern = r'port\s+(\d+)'
    ports_found = re.findall(port_pattern, question_lower)
    for port in ports_found:
        sql_parts.append(f"port = {port}")
        explanation_parts.append(f"filtered for port {port}")
    
    # 7. Detect Time Filters
    if "today" in question_lower:
        sql_parts.append("date(timestamp) = date('now')")
        explanation_parts.append("limited to today's records")
        metadata["time_filters"].append("today")
    elif "yesterday" in question_lower:
        sql_parts.append("date(timestamp) = date('now', '-1 day')")
        explanation_parts.append("limited to yesterday's records")
        metadata["time_filters"].append("yesterday")
    elif "last hour" in question_lower or "past hour" in question_lower:
        sql_parts.append("timestamp >= datetime('now', '-1 hour')")
        explanation_parts.append("limited to the last hour")
        metadata["time_filters"].append("last_hour")
    elif "last 24 hours" in question_lower or "past 24 hours" in question_lower:
        sql_parts.append("timestamp >= datetime('now', '-24 hours')")
        explanation_parts.append("limited to the last 24 hours")
        metadata["time_filters"].append("last_24_hours")
    elif "this week" in question_lower:
        sql_parts.append("timestamp >= datetime('now', '-7 days')")
        explanation_parts.append("limited to this week")
        metadata["time_filters"].append("this_week")
    elif "this month" in question_lower:
        sql_parts.append("timestamp >= datetime('now', '-30 days')")
        explanation_parts.append("limited to this month")
        metadata["time_filters"].append("this_month")
    
    # 8. Detect Byte/Size Filters
    if any(word in question_lower for word in ['high bytes', 'large transfer', 'data exfiltration', 'big data']):
        sql_parts.append("bytes > 50000")
        explanation_parts.append("filtered for high data transfer (>50KB)")
        metadata["custom_filters"].append("high_bytes")
    
    if any(word in question_lower for word in ['small packet', 'tiny', 'low bytes']):
        sql_parts.append("bytes < 100")
        explanation_parts.append("filtered for small packets (<100 bytes)")
        metadata["custom_filters"].append("small_bytes")
    
    # 9. Detect Duration Filters
    if any(word in question_lower for word in ['long connection', 'long duration', 'persistent']):
        sql_parts.append("duration > 300")
        explanation_parts.append("filtered for long connections (>5 minutes)")
        metadata["custom_filters"].append("long_duration")
    
    if any(word in question_lower for word in ['short connection', 'quick', 'brief']):
        sql_parts.append("duration < 1")
        explanation_parts.append("filtered for short connections (<1 second)")
        metadata["custom_filters"].append("short_duration")
    
    # 10. Detect Flag Filters
    if 'reset' in question_lower and 'flag' in question_lower:
        sql_parts.append("flag LIKE 'RST%'")
        explanation_parts.append("filtered for reset connections")
        metadata["custom_filters"].append("reset_flags")
    
    if 'syn' in question_lower and 'flag' in question_lower:
        sql_parts.append("flag = 'S0'")
        explanation_parts.append("filtered for SYN packets")
        metadata["custom_filters"].append("syn_flags")
    
    # Build Final Query
    sql_query = " AND ".join(sql_parts)
    sql_query += " ORDER BY timestamp DESC LIMIT 100"
    
    if len(sql_parts) == 1:
        sql_query = "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100"
        explanation_parts.append("returned all records (no specific filters detected)")
    
    return sql_query, explanation_parts, metadata


def generate_explanation(sql_query: str, df: pd.DataFrame, metadata: Dict) -> str:
    """Generate detailed human-readable explanation"""
    if df.empty:
        return "No matching records found for your query. Try different keywords."
    
    total_records = len(df)
    explanation = f"Found {total_records} records matching your query. "
    
    if metadata["attack_types_found"]:
        attack_str = ", ".join(metadata["attack_types_found"])
        explanation += f"The query focused on {attack_str} traffic. "
    
    if metadata["services_found"]:
        service_str = ", ".join(s.upper() for s in metadata["services_found"])
        explanation += f"Services analyzed: {service_str}. "
    
    if metadata["protocols_found"]:
        protocol_str = ", ".join(p.upper() for p in metadata["protocols_found"])
        explanation += f"Protocols included: {protocol_str}. "
    
    if metadata["ips_found"]:
        ip_str = ", ".join(metadata["ips_found"])
        explanation += f"Specific IPs analyzed: {ip_str}. "
    
    if metadata["actions_found"]:
        action_str = ", ".join(metadata["actions_found"])
        explanation += f"Actions filtered: {action_str}. "
    
    if metadata["time_filters"]:
        time_str = ", ".join(metadata["time_filters"])
        explanation += f"Time period: {time_str}. "
    
    if metadata["custom_filters"]:
        custom_str = ", ".join(metadata["custom_filters"])
        explanation += f"Additional filters: {custom_str}. "
    
    if 'attack_type' in df.columns:
        attack_count = len(df[df['attack_type'] != 'normal'])
        if attack_count > 0:
            explanation += f"Of these, {attack_count} are potential threats. "
            attack_types = df[df['attack_type'] != 'normal']['attack_type'].value_counts()
            if not attack_types.empty:
                top_attack = attack_types.index[0]
                explanation += f"Most common threat: '{top_attack}'."
    
    return explanation


def execute_ai_query(question: str) -> Dict:
    """Main function: Execute AI-powered query"""
    import time
    start_time = time.time()
    
    # Import risk scorer with correct path
    from utils.risk_scorer import calculate_risk_score, get_risk_level, analyze_threats
    
    # Translate question to SQL
    sql_query, explanation_parts, metadata = translate_question_to_sql(question)
    
    # Execute query
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(sql_query, conn)
    except Exception as e:
        conn.close()
        return {
            "success": False,
            "error": str(e),
            "question": question,
            "generated_query": sql_query
        }
    conn.close()
    
    response_time = (time.time() - start_time) * 1000
    
    # Generate explanation
    explanation = generate_explanation(sql_query, df, metadata)
    
    # Calculate risk score
    risk_score = calculate_risk_score(df)
    risk_level = get_risk_level(risk_score)
    threat_analysis = analyze_threats(df)
    
    # Save to query history
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO query_history 
        (question, generated_query, results_count, response_time_ms, risk_score) 
        VALUES (?, ?, ?, ?, ?)""",
        (question, sql_query, len(df), response_time, risk_score)
    )
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "question": question,
        "generated_query": sql_query,
        "explanation": explanation,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "results_count": len(df),
        "response_time_ms": round(response_time, 2),
        "metadata": metadata,
        "threat_analysis": threat_analysis,
        "data": df.to_dict('records')
    }


def test_ai_engine():
    """Test the AI engine with sample questions"""
    test_questions = [
        "Show me all brute force attacks",
        "Find denied SSH connections",
        "What DoS attacks happened today?",
        "Show me traffic from 192.168.1.100",
        "Find HTTP traffic with high bytes transfer",
        "Show me all normal traffic from yesterday"
    ]
    
    print("=" * 60)
    print("🧪 Testing QueryHunter AI Engine")
    print("=" * 60)
    
    for question in test_questions:
        print(f"\n❓ Question: {question}")
        result = execute_ai_query(question)
        
        if result["success"]:
            print(f"✅ Found {result['results_count']} records")
            print(f"📊 Risk Score: {result['risk_score']} ({result['risk_level']})")
            print(f"📝 Query: {result['generated_query'][:100]}...")
        else:
            print(f"❌ Error: {result['error']}")
        
        print("-" * 60)


if __name__ == "__main__":
    test_ai_engine()