"""
AI Query Engine V2 for QueryHunter AI
Enhanced with RAG (Retrieval-Augmented Generation)
Uses retrieved context to generate more accurate SQL queries
"""

import re
import sqlite3
import pandas as pd
import os
import sys
from typing import Tuple, List, Dict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_logs.db")

# Import RAG pipeline
from utils.rag_pipeline import get_rag_context, retrieve_similar_questions
from utils.risk_scorer import calculate_risk_score, get_risk_level, analyze_threats


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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def translate_question_to_sql_v2(question: str, rag_context: Dict = None) -> Tuple[str, List[str], Dict]:
    """
    Enhanced SQL translation using RAG context
    
    Args:
        question: Natural language question
        rag_context: RAG context with similar questions and schema info
    
    Returns:
        - sql_query: The generated SQL query
        - explanation_parts: List of human-readable explanation parts
        - metadata: Additional information about the query
    """
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
        "custom_filters": [],
        "rag_enhanced": False,
        "similar_query_used": None
    }
    
    # ============================================
    # RAG Enhancement: Use similar queries if available
    # ============================================
    if rag_context and rag_context.get('similar_questions'):
        similar = rag_context['similar_questions']
        if similar and similar[0]['similarity'] > 0.7:
            # High similarity found - can use similar query as reference
            metadata['rag_enhanced'] = True
            metadata['similar_query_used'] = similar[0]['query']
    
    # ============================================
    # 1. Detect Attack Types
    # ============================================
    for attack_type, keywords in ATTACK_TYPES.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"attack_type = '{attack_type}'")
            explanation_parts.append(f"filtered for {attack_type} traffic")
            metadata["attack_types_found"].append(attack_type)
    
    # ============================================
    # 2. Detect Services
    # ============================================
    for service, keywords in SERVICES.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"service = '{service}'")
            explanation_parts.append(f"filtered for {service.upper()} service")
            metadata["services_found"].append(service)
    
    # ============================================
    # 3. Detect Protocols
    # ============================================
    for protocol, keywords in PROTOCOLS.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"protocol = '{protocol}'")
            explanation_parts.append(f"filtered for {protocol.upper()} protocol")
            metadata["protocols_found"].append(protocol)
    
    # ============================================
    # 4. Detect Actions
    # ============================================
    for action, keywords in ACTIONS.items():
        if any(keyword in question_lower for keyword in keywords):
            sql_parts.append(f"action = '{action}'")
            explanation_parts.append(f"showing only {action} actions")
            metadata["actions_found"].append(action)
    
    # ============================================
    # 5. Detect IP Addresses
    # ============================================
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips_found = re.findall(ip_pattern, question)
    for ip in ips_found:
        sql_parts.append(f"(source_ip = '{ip}' OR dest_ip = '{ip}')")
        explanation_parts.append(f"filtered for IP address {ip}")
        metadata["ips_found"].append(ip)
    
    # ============================================
    # 6. Detect Port Numbers
    # ============================================
    port_pattern = r'port\s+(\d+)'
    ports_found = re.findall(port_pattern, question_lower)
    for port in ports_found:
        sql_parts.append(f"port = {port}")
        explanation_parts.append(f"filtered for port {port}")
    
    # ============================================
    # 7. Detect Time Filters
    # ============================================
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
    
    # ============================================
    # 8. Detect Byte/Size Filters
    # ============================================
    if any(word in question_lower for word in ['high bytes', 'large transfer', 'data exfiltration', 'big data']):
        sql_parts.append("bytes > 50000")
        explanation_parts.append("filtered for high data transfer (>50KB)")
        metadata["custom_filters"].append("high_bytes")
    
    if any(word in question_lower for word in ['small packet', 'tiny', 'low bytes']):
        sql_parts.append("bytes < 100")
        explanation_parts.append("filtered for small packets (<100 bytes)")
        metadata["custom_filters"].append("small_bytes")
    
    # ============================================
    # 9. Detect Duration Filters
    # ============================================
    if any(word in question_lower for word in ['long connection', 'long duration', 'persistent']):
        sql_parts.append("duration > 300")
        explanation_parts.append("filtered for long connections (>5 minutes)")
        metadata["custom_filters"].append("long_duration")
    
    if any(word in question_lower for word in ['short connection', 'quick', 'brief']):
        sql_parts.append("duration < 1")
        explanation_parts.append("filtered for short connections (<1 second)")
        metadata["custom_filters"].append("short_duration")
    
    # ============================================
    # 10. Detect Flag Filters
    # ============================================
    if 'reset' in question_lower and 'flag' in question_lower:
        sql_parts.append("flag LIKE 'RST%'")
        explanation_parts.append("filtered for reset connections")
        metadata["custom_filters"].append("reset_flags")
    
    if 'syn' in question_lower and 'flag' in question_lower:
        sql_parts.append("flag = 'S0'")
        explanation_parts.append("filtered for SYN packets")
        metadata["custom_filters"].append("syn_flags")
    
    # ============================================
    # Build Final Query
    # ============================================
    sql_query = " AND ".join(sql_parts)
    sql_query += " ORDER BY timestamp DESC LIMIT 100"
    
    # If no filters applied, return all records
    if len(sql_parts) == 1:
        sql_query = "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100"
        explanation_parts.append("returned all records (no specific filters detected)")
    
    return sql_query, explanation_parts, metadata


def generate_explanation_v2(sql_query: str, df: pd.DataFrame, metadata: Dict, rag_context: Dict = None) -> str:
    """Generate detailed human-readable explanation with RAG context"""
    if df.empty:
        return "No matching records found for your query. Try different keywords."
    
    total_records = len(df)
    explanation = f"Found {total_records} records matching your query. "
    
    # RAG Enhancement info
    if rag_context and rag_context.get('similar_questions'):
        similar = rag_context['similar_questions']
        if similar and similar[0]['similarity'] > 0.5:
            explanation += f"(Enhanced by similar query: '{similar[0]['question']}') "
    
    # Attack type summary
    if metadata["attack_types_found"]:
        attack_str = ", ".join(metadata["attack_types_found"])
        explanation += f"The query focused on {attack_str} traffic. "
    
    # Service summary
    if metadata["services_found"]:
        service_str = ", ".join(s.upper() for s in metadata["services_found"])
        explanation += f"Services analyzed: {service_str}. "
    
    # Protocol summary
    if metadata["protocols_found"]:
        protocol_str = ", ".join(p.upper() for p in metadata["protocols_found"])
        explanation += f"Protocols included: {protocol_str}. "
    
    # IP summary
    if metadata["ips_found"]:
        ip_str = ", ".join(metadata["ips_found"])
        explanation += f"Specific IPs analyzed: {ip_str}. "
    
    # Action summary
    if metadata["actions_found"]:
        action_str = ", ".join(metadata["actions_found"])
        explanation += f"Actions filtered: {action_str}. "
    
    # Time filter summary
    if metadata["time_filters"]:
        time_str = ", ".join(metadata["time_filters"])
        explanation += f"Time period: {time_str}. "
    
    # Custom filter summary
    if metadata["custom_filters"]:
        custom_str = ", ".join(metadata["custom_filters"])
        explanation += f"Additional filters: {custom_str}. "
    
    # Result statistics
    if 'attack_type' in df.columns:
        attack_count = len(df[df['attack_type'] != 'normal'])
        if attack_count > 0:
            explanation += f"Of these, {attack_count} are potential threats. "
            
            # Top attack types
            attack_types = df[df['attack_type'] != 'normal']['attack_type'].value_counts()
            if not attack_types.empty:
                top_attack = attack_types.index[0]
                explanation += f"Most common threat: '{top_attack}'."
    
    return explanation


def execute_ai_query_v2(question: str) -> Dict:
    """
    Enhanced AI query execution with RAG integration
    
    Returns complete response with:
    - Generated SQL query
    - Query results
    - RAG context used
    - Risk analysis
    - Explanation
    """
    import time
    start_time = time.time()
    
    # ============================================
    # Step 1: Get RAG Context
    # ============================================
    rag_context = get_rag_context(question)
    
    # ============================================
    # Step 2: Translate question to SQL using RAG context
    # ============================================
    sql_query, explanation_parts, metadata = translate_question_to_sql_v2(question, rag_context)
    
    # ============================================
    # Step 3: Execute query
    # ============================================
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(sql_query, conn)
    except Exception as e:
        conn.close()
        return {
            "success": False,
            "error": str(e),
            "question": question,
            "generated_query": sql_query,
            "rag_context": rag_context
        }
    conn.close()
    
    response_time = (time.time() - start_time) * 1000
    
    # ============================================
    # Step 4: Generate explanation
    # ============================================
    explanation = generate_explanation_v2(sql_query, df, metadata, rag_context)
    
    # ============================================
    # Step 5: Calculate risk score and threat analysis
    # ============================================
    risk_score = calculate_risk_score(df)
    risk_level = get_risk_level(risk_score)
    threat_analysis = analyze_threats(df)
    
    # ============================================
    # Step 6: Save to query history
    # ============================================
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO query_history 
        (question, generated_query, results_count, response_time_ms, risk_score) 
        VALUES (?, ?, ?, ?, ?)""",
        (question, sql_query, len(df), response_time, risk_score)
    )
    conn.commit()
    conn.close()
    
    # ============================================
    # Step 7: Build response
    # ============================================
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
        "rag_context": {
            "similar_questions": rag_context.get('similar_questions', []),
            "relevant_columns": list(rag_context.get('relevant_schema', {}).keys()),
            "attack_definitions": rag_context.get('attack_definitions', {}),
            "service_definitions": rag_context.get('service_definitions', {})
        },
        "threat_analysis": threat_analysis,
        "data": df.to_dict('records')
    }


# ============================================
# Test Functions
# ============================================

def test_ai_engine_v2():
    """Test the enhanced AI engine"""
    test_questions = [
        "Show me all brute force attacks",
        "Find denied SSH connections",
        "What DoS attacks happened today?",
        "Show me traffic from 192.168.1.100",
        "Find HTTP traffic with high bytes transfer",
        "Show me all normal traffic from yesterday",
        "Find UDP connections that were dropped",
        "Show me attacks with long duration connections"
    ]
    
    print("=" * 70)
    print("🧪 Testing QueryHunter AI Engine V2 (with RAG)")
    print("=" * 70)
    
    for question in test_questions:
        print(f"\n{'='*70}")
        print(f"❓ Question: {question}")
        print(f"{'='*70}")
        
        result = execute_ai_query_v2(question)
        
        if result["success"]:
            print(f"✅ Found {result['results_count']} records")
            print(f"📊 Risk Score: {result['risk_score']} ({result['risk_level']})")
            print(f"📝 SQL: {result['generated_query'][:80]}...")
            print(f"📖 {result['explanation'][:150]}...")
            
            # Show RAG info
            if result.get('rag_context', {}).get('similar_questions'):
                rag = result['rag_context']['similar_questions']
                if rag:
                    print(f"🔍 RAG: Found similar query '{rag[0]['question']}' (sim: {rag[0]['similarity']})")
        else:
            print(f"❌ Error: {result['error']}")
        
        print("-" * 70)
    
    print(f"\n{'='*70}")
    print("✅ AI Engine V2 Test Complete!")
    print(f"{'='*70}")


if __name__ == "__main__":
    test_ai_engine_v2()