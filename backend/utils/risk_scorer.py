"""
Risk Scoring Algorithm for QueryHunter AI
Calculates threat severity based on multiple security factors
"""

import pandas as pd
from typing import Dict, List
import os

# Get the absolute path to the database
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_logs.db")

def calculate_risk_score(df: pd.DataFrame) -> int:
    """
    Calculate risk score (0-100) based on attack patterns
    
    Scoring criteria:
    - Attack frequency: 0-30 points
    - Attack severity: 0-25 points
    - Data transfer anomalies: 0-20 points
    - Action patterns: 0-15 points
    - Source diversity: 0-10 points
    """
    if df.empty:
        return 0
    
    score = 0
    
    # ============================================
    # 1. Attack Frequency (0-30 points)
    # ============================================
    if 'attack_type' in df.columns:
        total_records = len(df)
        attack_records = len(df[df['attack_type'] != 'normal'])
        
        if total_records > 0:
            attack_ratio = attack_records / total_records
            
            if attack_ratio > 0.5:
                score += 30
            elif attack_ratio > 0.3:
                score += 20
            elif attack_ratio > 0.1:
                score += 10
            elif attack_ratio > 0:
                score += 5
    
    # ============================================
    # 2. Attack Severity (0-25 points)
    # ============================================
    if 'attack_type' in df.columns:
        # Critical attacks (brute force, DoS, U2R)
        critical_attacks = df[df['attack_type'].isin(['brute_force', 'dos', 'u2r'])]
        if len(critical_attacks) > 50:
            score += 25
        elif len(critical_attacks) > 20:
            score += 20
        elif len(critical_attacks) > 5:
            score += 15
        elif len(critical_attacks) > 0:
            score += 10
        
        # Medium severity attacks (R2L)
        r2l_attacks = df[df['attack_type'] == 'r2l']
        if len(r2l_attacks) > 20:
            score += 10
        elif len(r2l_attacks) > 0:
            score += 5
        
        # Low severity attacks (Probe)
        probe_attacks = df[df['attack_type'] == 'probe']
        if len(probe_attacks) > 30:
            score += 5
    
    # ============================================
    # 3. Data Transfer Anomalies (0-20 points)
    # ============================================
    if 'bytes' in df.columns:
        # High bytes transfer (potential data exfiltration)
        high_bytes = df[df['bytes'] > 50000]
        if len(high_bytes) > 20:
            score += 20
        elif len(high_bytes) > 10:
            score += 15
        elif len(high_bytes) > 5:
            score += 10
        elif len(high_bytes) > 0:
            score += 5
        
        # Very high bytes (definite exfiltration)
        very_high_bytes = df[df['bytes'] > 100000]
        if len(very_high_bytes) > 5:
            score += 10
    
    # ============================================
    # 4. Action Patterns (0-15 points)
    # ============================================
    if 'action' in df.columns:
        total_actions = len(df)
        
        # High denial rate
        denied = len(df[df['action'].isin(['DENY', 'DROP', 'RESET'])])
        if total_actions > 0:
            denial_ratio = denied / total_actions
            
            if denial_ratio > 0.7:
                score += 15
            elif denial_ratio > 0.5:
                score += 10
            elif denial_ratio > 0.3:
                score += 5
        
        # Reset connections (potential scanning)
        resets = len(df[df['action'] == 'RESET'])
        if resets > 20:
            score += 5
    
    # ============================================
    # 5. Source Diversity (0-10 points)
    # ============================================
    if 'source_ip' in df.columns:
        unique_sources = df['source_ip'].nunique()
        
        if unique_sources > 100:
            score += 10  # Potential DDoS
        elif unique_sources > 50:
            score += 7
        elif unique_sources > 20:
            score += 5
        elif unique_sources > 10:
            score += 3
    
    # ============================================
    # 6. Port Scanning Detection (bonus 0-10)
    # ============================================
    if 'port' in df.columns and 'source_ip' in df.columns:
        # Check if single IP hitting multiple ports
        ip_port_counts = df.groupby('source_ip')['port'].nunique()
        scanning_ips = ip_port_counts[ip_port_counts > 10]
        
        if len(scanning_ips) > 5:
            score += 10
        elif len(scanning_ips) > 0:
            score += 5
    
    return min(score, 100)


def get_risk_level(score: int) -> str:
    """Convert numeric score to risk level"""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"


def get_risk_color(score: int) -> str:
    """Get color code for risk level"""
    if score >= 80:
        return "#DC2626"  # Red
    elif score >= 60:
        return "#EA580C"  # Orange
    elif score >= 40:
        return "#D97706"  # Amber
    elif score >= 20:
        return "#CA8A04"  # Yellow
    else:
        return "#16A34A"  # Green


def analyze_threats(df: pd.DataFrame) -> Dict:
    """Comprehensive threat analysis"""
    if df.empty:
        return {
            "risk_score": 0,
            "risk_level": "MINIMAL",
            "total_records": 0,
            "threats_found": 0,
            "top_threats": [],
            "recommendations": []
        }
    
    risk_score = calculate_risk_score(df)
    risk_level = get_risk_level(risk_score)
    
    # Count threats
    threats = df[df['attack_type'] != 'normal'] if 'attack_type' in df.columns else pd.DataFrame()
    
    # Top attack types
    top_threats = []
    if 'attack_type' in df.columns and not threats.empty:
        threat_counts = threats['attack_type'].value_counts().head(5)
        top_threats = [{"type": k, "count": int(v)} for k, v in threat_counts.items()]
    
    # Generate recommendations
    recommendations = []
    if risk_score >= 80:
        recommendations.append("Immediate action required - consider blocking suspicious IPs")
        recommendations.append("Enable enhanced monitoring for affected systems")
    elif risk_score >= 60:
        recommendations.append("Review and potentially block high-risk source IPs")
        recommendations.append("Increase logging verbosity for affected services")
    elif risk_score >= 40:
        recommendations.append("Monitor traffic patterns for anomalies")
        recommendations.append("Verify firewall rules are up to date")
    elif risk_score >= 20:
        recommendations.append("Continue routine monitoring")
    else:
        recommendations.append("System appears healthy - maintain current security posture")
    
    # Add specific recommendations based on attack types
    if 'attack_type' in df.columns:
        if 'brute_force' in df['attack_type'].values:
            recommendations.append("Implement rate limiting and account lockout policies")
        if 'dos' in df['attack_type'].values:
            recommendations.append("Consider DDoS protection services")
        if 'probe' in df['attack_type'].values:
            recommendations.append("Review and close unnecessary open ports")
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_color": get_risk_color(risk_score),
        "total_records": len(df),
        "threats_found": len(threats),
        "top_threats": top_threats,
        "recommendations": recommendations
    }


def calculate_ip_risk(ip: str, df: pd.DataFrame) -> Dict:
    """Calculate risk score for a specific IP address"""
    ip_data = df[(df['source_ip'] == ip) | (df['dest_ip'] == ip)]
    
    if ip_data.empty:
        return {
            "ip": ip,
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "total_connections": 0,
            "attacks_initiated": 0,
            "attacks_received": 0
        }
    
    # Count attacks initiated
    attacks_initiated = len(ip_data[
        (ip_data['source_ip'] == ip) & (ip_data['attack_type'] != 'normal')
    ])
    
    # Count attacks received
    attacks_received = len(ip_data[
        (ip_data['dest_ip'] == ip) & (ip_data['attack_type'] != 'normal')
    ])
    
    # Calculate risk
    risk_score = calculate_risk_score(ip_data)
    
    return {
        "ip": ip,
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "total_connections": len(ip_data),
        "attacks_initiated": attacks_initiated,
        "attacks_received": attacks_received,
        "unique_destinations": ip_data['dest_ip'].nunique() if 'dest_ip' in ip_data.columns else 0,
        "unique_ports": ip_data['port'].nunique() if 'port' in ip_data.columns else 0
    }