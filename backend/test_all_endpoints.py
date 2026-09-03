"""
End-to-End Test for QueryHunter AI
Tests all API endpoints and verifies functionality
"""

import urllib.request
import urllib.error
import json
import time
import sys

# ============================================
# Configuration
# ============================================
BASE_URL = "http://localhost:8000"
TOTAL_TESTS = 0
PASSED_TESTS = 0
FAILED_TESTS = 0
TEST_RESULTS = []


def make_request(method, endpoint, data=None):
    """Make HTTP request and return response"""
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method == "GET":
            req = urllib.request.Request(url, method="GET")
        else:  # POST
            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(
                url, 
                data=json_data, 
                method="POST",
                headers={'Content-Type': 'application/json'}
            )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            status_code = response.getcode()
            body = response.read().decode('utf-8')
            return {
                "success": True,
                "status_code": status_code,
                "data": json.loads(body) if body else {}
            }
    except urllib.error.HTTPError as e:
        return {
            "success": False,
            "status_code": e.code,
            "data": e.read().decode('utf-8')
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": 0,
            "data": str(e)
        }


def test_endpoint(name, method, endpoint, data=None, expected_status=200, expected_fields=None):
    """Test a single endpoint"""
    global TOTAL_TESTS, PASSED_TESTS, FAILED_TESTS
    
    TOTAL_TESTS += 1
    
    print(f"\n{'='*60}")
    print(f"Test {TOTAL_TESTS}: {name}")
    print(f"{'='*60}")
    print(f"  {method} {endpoint}")
    if data:
        print(f"  Data: {json.dumps(data)[:80]}...")
    
    # Make request
    start_time = time.time()
    result = make_request(method, endpoint, data)
    response_time = (time.time() - start_time) * 1000
    
    # Check status code
    status_ok = result['status_code'] == expected_status
    
    # Check expected fields
    fields_ok = True
    missing_fields = []
    if expected_fields and result['success']:
        for field in expected_fields:
            if field not in result['data']:
                fields_ok = False
                missing_fields.append(field)
    
    # Determine pass/fail
    passed = status_ok and fields_ok
    
    if passed:
        PASSED_TESTS += 1
        status_icon = "✅"
        status_text = "PASS"
    else:
        FAILED_TESTS += 1
        status_icon = "❌"
        status_text = "FAIL"
    
    # Print results
    print(f"\n  Status: {status_icon} {status_text}")
    print(f"  Response Code: {result['status_code']}")
    print(f"  Response Time: {response_time:.2f}ms")
    
    if not status_ok:
        print(f"  ⚠️  Expected status {expected_status}, got {result['status_code']}")
    
    if missing_fields:
        print(f"  ⚠️  Missing fields: {', '.join(missing_fields)}")
    
    if result['success']:
        if 'success' in result['data']:
            print(f"  API Success: {result['data']['success']}")
        if 'count' in result['data']:
            print(f"  Record Count: {result['data']['count']}")
        if 'results_count' in result['data']:
            print(f"  Results Count: {result['data']['results_count']}")
        if 'risk_score' in result['data']:
            print(f"  Risk Score: {result['data']['risk_score']}")
        if 'risk_level' in result['data']:
            print(f"  Risk Level: {result['data']['risk_level']}")
    else:
        print(f"  Error: {str(result['data'])[:100]}")
    
    # Store result
    TEST_RESULTS.append({
        "name": name,
        "method": method,
        "endpoint": endpoint,
        "status": status_text,
        "response_time_ms": round(response_time, 2),
        "passed": passed
    })
    
    return passed


def run_all_tests():
    """Run all endpoint tests"""
    global TOTAL_TESTS, PASSED_TESTS, FAILED_TESTS
    
    print("\n" + "=" * 70)
    print("🧪 QueryHunter AI - End-to-End Test Suite")
    print("=" * 70)
    print(f"🌐 Target: {BASE_URL}")
    print(f"⏰ Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # ============================================
    # Test 1: Health Check
    # ============================================
    test_endpoint(
        "Health Check - Root",
        "GET",
        "/",
        expected_fields=["status", "service", "version"]
    )
    
    test_endpoint(
        "Health Check - /health",
        "GET",
        "/health",
        expected_fields=["status", "database"]
    )
    
    # ============================================
    # Test 2: Logs Endpoints
    # ============================================
    test_endpoint(
        "Get Logs (Default)",
        "GET",
        "/logs",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Get Logs (Limit 5)",
        "GET",
        "/logs?limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Get Logs (Filter by attack_type=dos)",
        "GET",
        "/logs?attack_type=dos&limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Get Logs (Filter by action=DENY)",
        "GET",
        "/logs?action=DENY&limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Get Logs (Filter by protocol=TCP)",
        "GET",
        "/logs?protocol=TCP&limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Get Logs (Filter by port=80)",
        "GET",
        "/logs?port=80&limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Get Logs (Filter by source_ip)",
        "GET",
        "/logs?source_ip=192.168.1.100&limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    # ============================================
    # Test 3: Stats Endpoint
    # ============================================
    test_endpoint(
        "Get Stats",
        "GET",
        "/stats",
        expected_fields=["success", "total_records", "attack_distribution", "top_source_ips"]
    )
    
    # ============================================
    # Test 4: Search Endpoint
    # ============================================
    test_endpoint(
        "Search Logs (q=brute)",
        "GET",
        "/search?q=brute&limit=5",
        expected_fields=["success", "query", "count", "data"]
    )
    
    test_endpoint(
        "Search Logs (q=192.168)",
        "GET",
        "/search?q=192.168&limit=5",
        expected_fields=["success", "query", "count", "data"]
    )
    
    test_endpoint(
        "Search Logs with Filters",
        "GET",
        "/search?q=ssh&attack_type=brute_force&limit=5",
        expected_fields=["success", "query", "count", "data"]
    )
    
    # ============================================
    # Test 5: Attack Types Endpoint
    # ============================================
    test_endpoint(
        "Get Attack Types",
        "GET",
        "/attack-types",
        expected_fields=["attack_types"]
    )
    
    # ============================================
    # Test 6: Training Data Endpoint
    # ============================================
    test_endpoint(
        "Get Training Data",
        "GET",
        "/training-data",
        expected_fields=["success", "count", "data"]
    )
    
    # ============================================
    # Test 7: Log by ID Endpoint
    # ============================================
    test_endpoint(
        "Get Log by ID (ID=1)",
        "GET",
        "/logs/1",
        expected_fields=["success", "data"]
    )
    
    test_endpoint(
        "Get Log by Invalid ID (ID=99999)",
        "GET",
        "/logs/99999",
        expected_status=404
    )
    
    # ============================================
    # Test 8: AI Ask Endpoint (Main Feature!)
    # ============================================
    test_endpoint(
        "AI Ask - Brute Force Attacks",
        "POST",
        "/ask",
        data={"question": "Show me all brute force attacks"},
        expected_fields=["success", "question", "generated_query", "explanation", "risk_score", "risk_level", "results_count", "rag_context", "data"]
    )
    
    test_endpoint(
        "AI Ask - Denied SSH Connections",
        "POST",
        "/ask",
        data={"question": "Find denied SSH connections"},
        expected_fields=["success", "question", "generated_query", "risk_score", "rag_context"]
    )
    
    test_endpoint(
        "AI Ask - DoS Attacks Today",
        "POST",
        "/ask",
        data={"question": "What DoS attacks happened today?"},
        expected_fields=["success", "question", "generated_query", "risk_score", "rag_context"]
    )
    
    test_endpoint(
        "AI Ask - Traffic from IP",
        "POST",
        "/ask",
        data={"question": "Show me traffic from 192.168.1.100"},
        expected_fields=["success", "question", "generated_query", "risk_score", "rag_context"]
    )
    
    test_endpoint(
        "AI Ask - HTTP High Bytes",
        "POST",
        "/ask",
        data={"question": "Find HTTP traffic with high bytes transfer"},
        expected_fields=["success", "question", "generated_query", "risk_score", "rag_context"]
    )
    
    test_endpoint(
        "AI Ask - Normal Traffic",
        "POST",
        "/ask",
        data={"question": "Show me all normal traffic"},
        expected_fields=["success", "question", "generated_query", "risk_score", "rag_context"]
    )
    
    test_endpoint(
        "AI Ask - UDP Dropped",
        "POST",
        "/ask",
        data={"question": "Find UDP connections that were dropped"},
        expected_fields=["success", "question", "generated_query", "risk_score", "rag_context"]
    )
    
    test_endpoint(
        "AI Ask - Empty Question",
        "POST",
        "/ask",
        data={"question": ""},
        expected_status=400
    )
    
    # ============================================
    # Test 9: RAG Context Endpoint
    # ============================================
    test_endpoint(
        "RAG Context",
        "GET",
        "/rag/context?q=Show me brute force attacks",
        expected_fields=["success", "question", "context"]
    )
    
    # ============================================
    # Test 10: RAG Similar Questions Endpoint
    # ============================================
    test_endpoint(
        "RAG Similar Questions",
        "GET",
        "/rag/similar?q=Find SSH attacks",
        expected_fields=["success", "question", "similar_questions"]
    )
    
    # ============================================
    # Test 11: Risk Analysis Endpoint
    # ============================================
    test_endpoint(
        "Risk Analysis - Brute Force",
        "GET",
        "/risk/analyze?attack_type=brute_force",
        expected_fields=["success", "analysis"]
    )
    
    test_endpoint(
        "Risk Analysis - Denied Actions",
        "GET",
        "/risk/analyze?action=DENY",
        expected_fields=["success", "analysis"]
    )
    
    # ============================================
    # Test 12: Query History Endpoint
    # ============================================
    test_endpoint(
        "Query History",
        "GET",
        "/query-history",
        expected_fields=["success", "count", "data"]
    )
    
    test_endpoint(
        "Query History (Limit 5)",
        "GET",
        "/query-history?limit=5",
        expected_fields=["success", "count", "data"]
    )
    
    # ============================================
    # Print Summary
    # ============================================
    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)
    print(f"\nTotal Tests: {TOTAL_TESTS}")
    print(f"✅ Passed: {PASSED_TESTS}")
    print(f"❌ Failed: {FAILED_TESTS}")
    print(f"📈 Success Rate: {(PASSED_TESTS/TOTAL_TESTS*100):.1f}%")
    
    print(f"\n{'='*70}")
    print("⏱️  RESPONSE TIMES")
    print(f"{'='*70}")
    
    # Calculate stats
    response_times = [r['response_time_ms'] for r in TEST_RESULTS]
    if response_times:
        print(f"  Average: {sum(response_times)/len(response_times):.2f}ms")
        print(f"  Min: {min(response_times):.2f}ms")
        print(f"  Max: {max(response_times):.2f}ms")
    
    print(f"\n{'='*70}")
    print("📋 DETAILED RESULTS")
    print(f"{'='*70}")
    
    for result in TEST_RESULTS:
        icon = "✅" if result['passed'] else "❌"
        print(f"  {icon} [{result['status']}] {result['name']} ({result['response_time_ms']:.2f}ms)")
    
    if FAILED_TESTS > 0:
        print(f"\n{'='*70}")
        print("❌ FAILED TESTS")
        print(f"{'='*70}")
        for result in TEST_RESULTS:
            if not result['passed']:
                print(f"  • {result['name']}")
                print(f"    {result['method']} {result['endpoint']}")
    
    print(f"\n{'='*70}")
    print(f"⏰ Finished: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    return FAILED_TESTS == 0


if __name__ == "__main__":
    # Check if server is running
    print("🔍 Checking if server is running...")
    try:
        req = urllib.request.Request(f"{BASE_URL}/health")
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            print(f"✅ Server is running (Database: {data.get('database', 'unknown')})")
    except Exception as e:
        print(f"❌ Server is not running!")
        print(f"   Error: {e}")
        print(f"\n⚠️  Start the server first with: python main.py")
        sys.exit(1)
    
    # Run tests
    success = run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)