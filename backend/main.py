"""
QueryHunter AI - Main Backend Server
FastAPI server with AI-powered natural language query processing
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import pandas as pd
from typing import Optional
from datetime import datetime
import time
import os

# Get the absolute path to the database
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "security_logs.db")

# Import AI Engine V2 with RAG
from utils.ai_engine_v2 import execute_ai_query_v2
from utils.risk_scorer import calculate_risk_score, get_risk_level, analyze_threats
from utils.rag_pipeline import get_rag_context, retrieve_similar_questions

# ============================================
# Initialize FastAPI App
# ============================================
app = FastAPI(
    title="QueryHunter AI",
    description="AI-Powered Security Log Analyzer",
    version="2.0.0"
)

# Enable CORS (so frontend can connect)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# Helper Functions
# ============================================

def get_db_connection():
    """Get database connection"""
    if not os.path.exists(DB_PATH):
        raise HTTPException(
            status_code=500, 
            detail="Database not found. Run setup_database.py first."
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================
# API Endpoints
# ============================================

@app.get("/")
def home():
    """Health check endpoint"""
    return {
        "status": "running",
        "service": "QueryHunter AI Backend",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
def health_check():
    """Detailed health check"""
    db_status = "connected" if os.path.exists(DB_PATH) else "disconnected"
    return {
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/logs")
def get_logs(
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    attack_type: Optional[str] = None,
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    source_ip: Optional[str] = None,
    port: Optional[int] = None
):
    """Get security logs with optional filtering"""
    start_time = time.time()
    
    conn = get_db_connection()
    
    # Build query dynamically
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    
    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)
    
    if action:
        query += " AND action = ?"
        params.append(action)
    
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)
    
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    
    if port:
        query += " AND port = ?"
        params.append(port)
    
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    
    response_time = (time.time() - start_time) * 1000
    
    return {
        "success": True,
        "count": len(df),
        "response_time_ms": round(response_time, 2),
        "data": df.to_dict('records')
    }

@app.get("/stats")
def get_stats():
    """Get attack statistics and summaries"""
    conn = get_db_connection()
    
    # Attack type distribution
    attack_counts = pd.read_sql_query(
        """SELECT attack_type, COUNT(*) as count, 
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM logs), 2) as percentage 
        FROM logs GROUP BY attack_type ORDER BY count DESC""",
        conn
    )
    
    # Top source IPs
    top_source_ips = pd.read_sql_query(
        "SELECT source_ip, COUNT(*) as count FROM logs GROUP BY source_ip ORDER BY count DESC LIMIT 10",
        conn
    )
    
    # Top destination IPs
    top_dest_ips = pd.read_sql_query(
        "SELECT dest_ip, COUNT(*) as count FROM logs GROUP BY dest_ip ORDER BY count DESC LIMIT 10",
        conn
    )
    
    # Top ports
    top_ports = pd.read_sql_query(
        "SELECT port, service, COUNT(*) as count FROM logs GROUP BY port ORDER BY count DESC LIMIT 10",
        conn
    )
    
    # Action distribution
    action_counts = pd.read_sql_query(
        "SELECT action, COUNT(*) as count FROM logs GROUP BY action ORDER BY count DESC",
        conn
    )
    
    # Hourly traffic pattern
    hourly_traffic = pd.read_sql_query(
        "SELECT strftime('%H', timestamp) as hour, COUNT(*) as count FROM logs GROUP BY hour ORDER BY hour",
        conn
    )
    
    # Daily attack trend
    daily_attacks = pd.read_sql_query(
        """SELECT date(timestamp) as date, COUNT(*) as total, 
        SUM(CASE WHEN attack_type != 'normal' THEN 1 ELSE 0 END) as attacks 
        FROM logs GROUP BY date(timestamp) ORDER BY date""",
        conn
    )
    
    # Total records
    total_records = pd.read_sql_query("SELECT COUNT(*) as count FROM logs", conn).iloc[0]['count']
    
    conn.close()
    
    return {
        "success": True,
        "total_records": int(total_records),
        "attack_distribution": attack_counts.to_dict('records'),
        "top_source_ips": top_source_ips.to_dict('records'),
        "top_destination_ips": top_dest_ips.to_dict('records'),
        "top_ports": top_ports.to_dict('records'),
        "action_distribution": action_counts.to_dict('records'),
        "hourly_traffic": hourly_traffic.to_dict('records'),
        "daily_attack_trend": daily_attacks.to_dict('records')
    }

@app.get("/search")
def search_logs(
    q: str = Query(default="", description="Search query"),
    attack_type: Optional[str] = None,
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500)
):
    """Search logs with multiple filters"""
    conn = get_db_connection()
    
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    
    if q:
        query += " AND (source_ip LIKE ? OR dest_ip LIKE ? OR attack_type LIKE ? OR service LIKE ?)"
        search_term = f"%{q}%"
        params.extend([search_term, search_term, search_term, search_term])
    
    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)
    
    if action:
        query += " AND action = ?"
        params.append(action)
    
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    
    return {
        "success": True,
        "query": q,
        "count": len(df),
        "data": df.to_dict('records')
    }

@app.get("/attack-types")
def get_attack_types():
    """Get all unique attack types"""
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT DISTINCT attack_type FROM logs ORDER BY attack_type", conn)
    conn.close()
    return {"attack_types": df['attack_type'].tolist()}

@app.get("/training-data")
def get_training_data():
    """Get AI training data (question-query pairs)"""
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM training_data ORDER BY id", conn)
    conn.close()
    return {
        "success": True,
        "count": len(df),
        "data": df.to_dict('records')
    }

@app.get("/logs/{log_id}")
def get_log_by_id(log_id: int):
    """Get a specific log entry by ID"""
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM logs WHERE id = ?", conn, params=[log_id])
    conn.close()
    
    if df.empty:
        raise HTTPException(status_code=404, detail=f"Log with ID {log_id} not found")
    
    return {"success": True, "data": df.iloc[0].to_dict()}

@app.get("/query-history")
def get_query_history(limit: int = Query(default=20, ge=1, le=100)):
    """Get recent query history"""
    conn = get_db_connection()
    df = pd.read_sql_query(
        "SELECT * FROM query_history ORDER BY created_at DESC LIMIT ?",
        conn,
        params=[limit]
    )
    conn.close()
    return {
        "success": True,
        "count": len(df),
        "data": df.to_dict('records')
    }

# ============================================
# AI Endpoints (Main Feature)
# ============================================

@app.post("/ask")
async def ask_question(request: dict):
    """
    AI-powered natural language query endpoint (V2 with RAG)
    Translates English questions to SQL and returns results with RAG context
    """
    question = request.get("question", "").strip()
    
    if not question:
        raise HTTPException(status_code=400, detail="Question is required")
    
    # Use AI Engine V2 with RAG
    result = execute_ai_query_v2(question)
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Query failed"))
    
    return result

@app.post("/ask/simple")
async def ask_question_simple(request: dict):
    """
    Simple AI query without RAG (for comparison)
    """
    question = request.get("question", "").strip()
    
    if not question:
        raise HTTPException(status_code=400, detail="Question is required")
    
    from utils.ai_engine import execute_ai_query
    
    result = execute_ai_query(question)
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Query failed"))
    
    return result

@app.get("/rag/context")
def get_rag_context_endpoint(q: str = Query(..., description="Question to get RAG context for")):
    """Get RAG context for a question (for debugging/understanding)"""
    context = get_rag_context(q)
    return {
        "success": True,
        "question": q,
        "context": context
    }

@app.get("/rag/similar")
def get_similar_questions(q: str = Query(..., description="Question to find similar queries for")):
    """Find similar questions from training data"""
    similar = retrieve_similar_questions(q, top_k=5)
    return {
        "success": True,
        "question": q,
        "similar_questions": similar
    }

@app.get("/risk/analyze")
def analyze_risk(
    attack_type: Optional[str] = None,
    action: Optional[str] = None,
    protocol: Optional[str] = None
):
    """Analyze risk for filtered data"""
    conn = get_db_connection()
    
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    
    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)
    
    if action:
        query += " AND action = ?"
        params.append(action)
    
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)
    
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    
    analysis = analyze_threats(df)
    
    return {
        "success": True,
        "filters": {
            "attack_type": attack_type,
            "action": action,
            "protocol": protocol
        },
        "analysis": analysis
    }

# ============================================
# Run the Server
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "=" * 60)
    print("🛡️  QueryHunter AI Backend Server V2.0")
    print("=" * 60)
    print(f"\n📡 Server running at: http://localhost:8000")
    print(f"📚 API Documentation: http://localhost:8000/docs")
    print(f"🔍 Health Check: http://localhost:8000/health")
    print(f"🤖 AI Query: http://localhost:8000/ask (POST)")
    print(f"🔍 RAG Context: http://localhost:8000/rag/context?q=your+question")
    print(f"\n⚠️  Press CTRL+C to stop the server\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)