"""
RAG Pipeline for QueryHunter AI
Retrieves relevant context from training data and log schemas
Improves AI query accuracy using vector search
"""

import sqlite3
import pandas as pd
import os
import sys
import re
from typing import List, Dict, Tuple
from collections import Counter

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_logs.db")


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================
# Log Schema Knowledge Base
# ============================================

LOG_SCHEMA = {
    "table_name": "logs",
    "columns": {
        "id": {"type": "INTEGER", "description": "Unique identifier for each log entry"},
        "timestamp": {"type": "TEXT", "description": "Date and time of the event (YYYY-MM-DD HH:MM:SS)"},
        "source_ip": {"type": "TEXT", "description": "IP address that initiated the connection"},
        "dest_ip": {"type": "TEXT", "description": "IP address that received the connection"},
        "protocol": {"type": "TEXT", "description": "Network protocol: TCP, UDP, or ICMP"},
        "port": {"type": "INTEGER", "description": "Destination port number"},
        "service": {"type": "TEXT", "description": "Network service: http, https, ssh, dns, ftp, smtp, telnet, rdp"},
        "action": {"type": "TEXT", "description": "Firewall action: ALLOW, DENY, DROP, RESET"},
        "bytes": {"type": "INTEGER", "description": "Number of bytes transferred in the connection"},
        "duration": {"type": "REAL", "description": "Duration of the connection in seconds"},
        "flag": {"type": "TEXT", "description": "Connection status flag (SF, S0, REJ, RSTR, etc.)"},
        "attack_type": {"type": "TEXT", "description": "Type of attack: normal, probe, dos, r2l, u2r, brute_force"},
        "attack_label": {"type": "INTEGER", "description": "Binary label: 0 for normal, 1 for attack"}
    }
}

ATTACK_TYPE_DEFINITIONS = {
    "normal": "Legitimate network traffic with no malicious intent",
    "probe": "Scanning or reconnaissance activity to discover network vulnerabilities",
    "dos": "Denial of Service attack attempting to make services unavailable",
    "r2l": "Remote to Local attack where unauthorized access is gained from a remote machine",
    "u2r": "User to Root attack where local user gains unauthorized root privileges",
    "brute_force": "Repeated attempts to guess passwords or credentials through trial and error"
}

SERVICE_DEFINITIONS = {
    "http": "Hypertext Transfer Protocol - web traffic on port 80",
    "https": "Secure HTTP - encrypted web traffic on port 443",
    "ssh": "Secure Shell - encrypted remote login on port 22",
    "dns": "Domain Name System - name resolution on port 53",
    "ftp": "File Transfer Protocol - file transfers on port 21",
    "smtp": "Simple Mail Transfer Protocol - email on port 25",
    "telnet": "Unencrypted remote login on port 23",
    "rdp": "Remote Desktop Protocol on port 3389"
}


# ============================================
# Simple TF-IDF Vectorizer (No external dependencies)
# ============================================

class SimpleVectorizer:
    """Simple TF-IDF-like vectorizer for text similarity"""
    
    def __init__(self):
        self.vocabulary = {}
        self.idf_values = {}
        self.documents = []
    
    def fit(self, documents: List[str]):
        """Build vocabulary and IDF values from documents"""
        self.documents = documents
        
        # Tokenize and build vocabulary
        all_tokens = []
        doc_token_counts = []
        
        for doc in documents:
            tokens = self._tokenize(doc)
            doc_token_counts.append(Counter(tokens))
            all_tokens.extend(tokens)
        
        # Build vocabulary
        unique_tokens = list(set(all_tokens))
        self.vocabulary = {token: idx for idx, token in enumerate(unique_tokens)}
        
        # Calculate IDF
        n_docs = len(documents)
        for token in unique_tokens:
            docs_with_token = sum(1 for counts in doc_token_counts if token in counts)
            self.idf_values[token] = 1 + (n_docs / (1 + docs_with_token))
    
    def transform(self, documents: List[str]) -> List[Dict[int, float]]:
        """Transform documents to TF-IDF vectors"""
        vectors = []
        
        for doc in documents:
            tokens = self._tokenize(doc)
            token_counts = Counter(tokens)
            total_tokens = len(tokens) if tokens else 1
            
            vector = {}
            for token, count in token_counts.items():
                if token in self.vocabulary:
                    tf = count / total_tokens
                    idf = self.idf_values.get(token, 1.0)
                    vector[self.vocabulary[token]] = tf * idf
            
            vectors.append(vector)
        
        return vectors
    
    def fit_transform(self, documents: List[str]) -> List[Dict[int, float]]:
        """Fit and transform documents"""
        self.fit(documents)
        return self.transform(documents)
    
    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization"""
        text = text.lower()
        tokens = re.findall(r'\b[a-z0-9]+\b', text)
        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                      'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
                      'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'dare',
                      'ought', 'used', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by',
                      'from', 'as', 'into', 'through', 'during', 'before', 'after',
                      'above', 'below', 'between', 'under', 'again', 'further', 'then',
                      'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all',
                      'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor',
                      'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'just',
                      'and', 'but', 'if', 'or', 'because', 'until', 'while', 'this', 'that',
                      'these', 'those', 'am', 'me', 'my', 'we', 'our', 'you', 'your', 'he',
                      'him', 'his', 'she', 'her', 'it', 'its', 'they', 'them', 'their',
                      'what', 'which', 'who', 'whom', 'about', 'against', 'down', 'out',
                      'off', 'over', 'under', 'again', 'further', 'then', 'once'}
        return [t for t in tokens if t not in stop_words and len(t) > 1]


def cosine_similarity(vec1: Dict[int, float], vec2: Dict[int, float]) -> float:
    """Calculate cosine similarity between two sparse vectors"""
    # Find common indices
    common_indices = set(vec1.keys()) & set(vec2.keys())
    
    if not common_indices:
        return 0.0
    
    # Calculate dot product
    dot_product = sum(vec1[idx] * vec2[idx] for idx in common_indices)
    
    # Calculate magnitudes
    mag1 = sum(v ** 2 for v in vec1.values()) ** 0.5
    mag2 = sum(v ** 2 for v in vec2.values()) ** 0.5
    
    if mag1 == 0 or mag2 == 0:
        return 0.0
    
    return dot_product / (mag1 * mag2)


# ============================================
# RAG Pipeline Class
# ============================================

class RAGPipeline:
    """Retrieval-Augmented Generation pipeline for query enhancement"""
    
    def __init__(self):
        self.vectorizer = SimpleVectorizer()
        self.training_data = []
        self.training_questions = []
        self.vectors = []
        self._load_training_data()
        self._build_index()
    
    def _load_training_data(self):
        """Load training data from database"""
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM training_data ORDER BY id", conn)
        conn.close()
        
        self.training_data = df.to_dict('records')
        self.training_questions = [item['question'] for item in self.training_data]
    
    def _build_index(self):
        """Build vector index for training questions"""
        if self.training_questions:
            self.vectors = self.vectorizer.fit_transform(self.training_questions)
    
    def retrieve_similar_questions(self, query: str, top_k: int = 3) -> List[Dict]:
        """Retrieve similar questions from training data"""
        if not self.vectors:
            return []
        
        # Transform query
        query_vector = self.vectorizer.transform([query])[0]
        
        # Calculate similarities
        similarities = []
        for idx, vec in enumerate(self.vectors):
            sim = cosine_similarity(query_vector, vec)
            if sim > 0.1:  # Minimum similarity threshold
                similarities.append({
                    "question": self.training_data[idx]['question'],
                    "query": self.training_data[idx]['query'],
                    "explanation": self.training_data[idx]['explanation'],
                    "similarity": round(sim, 4)
                })
        
        # Sort by similarity and return top_k
        similarities.sort(key=lambda x: x['similarity'], reverse=True)
        return similarities[:top_k]
    
    def get_relevant_schema(self, query: str) -> Dict:
        """Get relevant schema information based on query"""
        query_lower = query.lower()
        relevant_columns = {}
        
        # Check for attack type related queries
        if any(word in query_lower for word in ['attack', 'threat', 'malicious', 'dos', 'brute force', 'probe']):
            relevant_columns['attack_type'] = LOG_SCHEMA['columns']['attack_type']
            relevant_columns['attack_label'] = LOG_SCHEMA['columns']['attack_label']
        
        # Check for IP related queries
        if any(word in query_lower for word in ['ip', 'source', 'destination', 'address']):
            relevant_columns['source_ip'] = LOG_SCHEMA['columns']['source_ip']
            relevant_columns['dest_ip'] = LOG_SCHEMA['columns']['dest_ip']
        
        # Check for protocol related queries
        if any(word in query_lower for word in ['protocol', 'tcp', 'udp', 'icmp']):
            relevant_columns['protocol'] = LOG_SCHEMA['columns']['protocol']
        
        # Check for service/port related queries
        if any(word in query_lower for word in ['service', 'port', 'http', 'ssh', 'dns', 'ftp']):
            relevant_columns['service'] = LOG_SCHEMA['columns']['service']
            relevant_columns['port'] = LOG_SCHEMA['columns']['port']
        
        # Check for action related queries
        if any(word in query_lower for word in ['allow', 'deny', 'drop', 'block', 'action']):
            relevant_columns['action'] = LOG_SCHEMA['columns']['action']
        
        # Check for bytes/size related queries
        if any(word in query_lower for word in ['bytes', 'size', 'transfer', 'exfiltration']):
            relevant_columns['bytes'] = LOG_SCHEMA['columns']['bytes']
        
        # Check for duration related queries
        if any(word in query_lower for word in ['duration', 'time', 'connection', 'long', 'short']):
            relevant_columns['duration'] = LOG_SCHEMA['columns']['duration']
        
        # Check for flag related queries
        if any(word in query_lower for word in ['flag', 'status', 'reset', 'syn']):
            relevant_columns['flag'] = LOG_SCHEMA['columns']['flag']
        
        # Check for time related queries
        if any(word in query_lower for word in ['today', 'yesterday', 'hour', 'week', 'month', 'time']):
            relevant_columns['timestamp'] = LOG_SCHEMA['columns']['timestamp']
        
        return relevant_columns
    
    def get_attack_definitions(self, query: str) -> Dict[str, str]:
        """Get relevant attack type definitions"""
        query_lower = query.lower()
        definitions = {}
        
        for attack_type, definition in ATTACK_TYPE_DEFINITIONS.items():
            if attack_type in query_lower:
                definitions[attack_type] = definition
        
        return definitions
    
    def get_service_definitions(self, query: str) -> Dict[str, str]:
        """Get relevant service definitions"""
        query_lower = query.lower()
        definitions = {}
        
        for service, definition in SERVICE_DEFINITIONS.items():
            if service in query_lower:
                definitions[service] = definition
        
        return definitions
    
    def get_available_values(self, column: str) -> List[str]:
        """Get distinct values for a column"""
        conn = get_db_connection()
        try:
            df = pd.read_sql_query(f"SELECT DISTINCT {column} FROM logs ORDER BY {column}", conn)
            values = df[column].tolist()
        except:
            values = []
        conn.close()
        return values
    
    def augment_query(self, question: str) -> Dict:
        """
        Main RAG function: Augment question with relevant context
        
        Returns context dictionary with:
        - similar_questions: Past similar queries
        - relevant_schema: Relevant table columns
        - attack_definitions: Attack type explanations
        - service_definitions: Service explanations
        - sample_values: Example values for relevant columns
        """
        context = {
            "original_question": question,
            "similar_questions": self.retrieve_similar_questions(question),
            "relevant_schema": self.get_relevant_schema(question),
            "attack_definitions": self.get_attack_definitions(question),
            "service_definitions": self.get_service_definitions(question),
            "sample_values": {}
        }
        
        # Get sample values for relevant columns
        for column in context['relevant_schema']:
            values = self.get_available_values(column)
            if values:
                context['sample_values'][column] = values[:10]  # Top 10 values
        
        return context
    
    def generate_enhanced_prompt(self, question: str) -> str:
        """Generate enhanced prompt with RAG context"""
        context = self.augment_query(question)
        
        prompt_parts = [f"Question: {question}\n"]
        
        # Add similar questions context
        if context['similar_questions']:
            prompt_parts.append("Similar past queries:")
            for sq in context['similar_questions']:
                prompt_parts.append(f"  - '{sq['question']}' → SQL: {sq['query']}")
        
        # Add relevant schema
        if context['relevant_schema']:
            prompt_parts.append("\nRelevant columns:")
            for col, info in context['relevant_schema'].items():
                prompt_parts.append(f"  - {col}: {info['description']}")
        
        # Add attack definitions
        if context['attack_definitions']:
            prompt_parts.append("\nAttack type definitions:")
            for attack, definition in context['attack_definitions'].items():
                prompt_parts.append(f"  - {attack}: {definition}")
        
        # Add service definitions
        if context['service_definitions']:
            prompt_parts.append("\nService definitions:")
            for service, definition in context['service_definitions'].items():
                prompt_parts.append(f"  - {service}: {definition}")
        
        # Add sample values
        if context['sample_values']:
            prompt_parts.append("\nAvailable values:")
            for col, values in context['sample_values'].items():
                prompt_parts.append(f"  - {col}: {', '.join(str(v) for v in values[:5])}")
        
        return "\n".join(prompt_parts)


# ============================================
# Global RAG Instance
# ============================================

rag_pipeline = RAGPipeline()


# ============================================
# Public Functions
# ============================================

def get_rag_context(question: str) -> Dict:
    """Get RAG context for a question"""
    return rag_pipeline.augment_query(question)


def generate_rag_prompt(question: str) -> str:
    """Generate enhanced prompt with RAG context"""
    return rag_pipeline.generate_enhanced_prompt(question)


def retrieve_similar_questions(question: str, top_k: int = 3) -> List[Dict]:
    """Retrieve similar questions from training data"""
    return rag_pipeline.retrieve_similar_questions(question, top_k)


# ============================================
# Test Functions
# ============================================

def test_rag_pipeline():
    """Test the RAG pipeline"""
    test_questions = [
        "Show me all brute force attacks",
        "Find denied SSH connections",
        "What DoS attacks happened today?",
        "Show me traffic from 192.168.1.100",
        "Find HTTP traffic with high bytes transfer"
    ]
    
    print("=" * 70)
    print("🧪 Testing QueryHunter RAG Pipeline")
    print("=" * 70)
    
    for question in test_questions:
        print(f"\n{'='*70}")
        print(f"❓ Question: {question}")
        print(f"{'='*70}")
        
        # Get RAG context
        context = get_rag_context(question)
        
        # Display similar questions
        if context['similar_questions']:
            print(f"\n📚 Similar Questions Found: {len(context['similar_questions'])}")
            for sq in context['similar_questions']:
                print(f"   • '{sq['question']}' (similarity: {sq['similarity']})")
                print(f"     SQL: {sq['query']}")
        
        # Display relevant schema
        if context['relevant_schema']:
            print(f"\n📊 Relevant Columns: {', '.join(context['relevant_schema'].keys())}")
        
        # Display definitions
        if context['attack_definitions']:
            print(f"\n⚠️  Attack Types:")
            for attack, definition in context['attack_definitions'].items():
                print(f"   • {attack}: {definition}")
        
        if context['service_definitions']:
            print(f"\n🔧 Services:")
            for service, definition in context['service_definitions'].items():
                print(f"   • {service}: {definition}")
        
        # Display sample values
        if context['sample_values']:
            print(f"\n📋 Sample Values:")
            for col, values in context['sample_values'].items():
                print(f"   • {col}: {', '.join(str(v) for v in values[:5])}")
        
        # Display enhanced prompt
        enhanced_prompt = generate_rag_prompt(question)
        print(f"\n📝 Enhanced Prompt Preview:")
        print(f"   {enhanced_prompt[:200]}...")
    
    print(f"\n{'='*70}")
    print("✅ RAG Pipeline Test Complete!")
    print(f"{'='*70}")


if __name__ == "__main__":
    test_rag_pipeline()