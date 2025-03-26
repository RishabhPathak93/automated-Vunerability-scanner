import os
import glob
import time
import queue
import threading
import re
import logging
from functools import lru_cache
from pymongo import MongoClient
import uuid
from datetime import datetime
from bson import ObjectId
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import OllamaEmbeddings
from langchain_core.documents import Document
from langchain.chains import RetrievalQA
from langchain_community.llms import Ollama
from threading import Lock  

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global scan progress tracking
GLOBAL_SCAN_PROGRESS = {}
GLOBAL_SCAN_PROGRESS_LOCK = Lock()

# MongoDB Configuration
MONGO_URI = "mongodb+srv://astraaccess:hbf3bcyZhcb3ycb@astrart.ccqas.mongodb.net/NewReportingtool?retryWrites=true&w=majority&appName=AstraRT"
DB_NAME = "Reportingtool"
COLLECTION_NAME = "findings"
MAX_TOKENS = 1024  

# Queue for managing scan tasks
scan_queue = queue.Queue()
progress_lock = threading.Lock()

def get_source_files(folder_path):
    """Get all source code files from the folder."""
    supported_extensions = ["py", "js", "java", "c", "cpp", "go", "php", "rb", "ts", "jsx"]
    files = [f for ext in supported_extensions for f in glob.glob(os.path.join(folder_path, f"**/*.{ext}"), recursive=True)]
    return files

@lru_cache(maxsize=1)
def get_llm():
    """Load LLM model."""
    return Ollama(model="codellama:7b")

def setup_knowledge_base():
    """Set up the knowledge base for security vulnerabilities."""
    documents = [
        Document(page_content="SQL Injection allows attackers to execute arbitrary SQL queries.", metadata={"source": "OWASP"}),
        Document(page_content="Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.", metadata={"source": "OWASP"}),
        Document(page_content="Use prepared statements to prevent SQL Injection.", metadata={"source": "Best Practices"}),
        Document(page_content="Sanitize user input to prevent XSS attacks.", metadata={"source": "Best Practices"}),
    ]
    embeddings = OllamaEmbeddings(model="codellama")
    return FAISS.from_documents(documents, embeddings)

def extract_vulnerable_function(file_content, snippet):
    """Extract the function or class surrounding the vulnerable code."""
    pattern = re.compile(r"(\bdef\b|\bfunction\b|\bclass\b).*?\n.*?" + re.escape(snippet) + r".*?\n(?:}|\n)", re.DOTALL)
    match = pattern.search(file_content)
    return match.group(0) if match else snippet

def extract_relevant_info(output, file_name, engagement, owner, file_content):
    """Extract relevant security vulnerabilities from the LLM output."""
    if not output or not isinstance(output, str):
        return []

    vulnerabilities = []
    pattern = re.compile(
        r"Vulnerability:\s*(.*?)\s*\n"
        r"CWE:\s*(.*?)\s*\n"
        r"Severity:\s*(.*?)\s*\n"
        r"Impact:\s*(.*?)\s*\n"
        r"Mitigation:\s*(.*?)\s*\n"
        r"Affected:\s*(.*?)\s*\n"
        r"Code Snippet:\s*(.*?)\s*(?:\n|$)",  
        re.DOTALL
    )
    matches = pattern.findall(output)
    
    for match in matches:
        vulnerable_code_snippet = match[6].strip()
        full_vulnerable_code = extract_vulnerable_function(file_content, vulnerable_code_snippet)

        vulnerabilities.append({
            "title": match[0].strip(),
            "CWE": match[1].strip(),
            "severity": match[2].strip(),
            "impact": match[3].strip(),
            "mitigation": match[4].strip(),
            "affected": f"{file_name} - {match[5].strip()}",
            "engagement": ObjectId(engagement),
            "code": 'F-' + str(uuid.uuid4()).replace('-', '')[:8],
            "owner": ObjectId(owner),
            "cvss_vector": "NA",
            "cvss_score": "NA",
            "reference": "NA",
            "assistance": "ASCR",
            "pocpic": full_vulnerable_code,
            "pocdesc": "[]",
            "rpoc": "[]",
            "rpocdesc": "[]",
            "under_reval": False,
            "approved": False,
            "status": "OPEN",
            "deleted": False,
            "createdAt": datetime.utcnow().isoformat(timespec='milliseconds') + 'Z',
        })

    return vulnerabilities

def scan_single_file(file_path, engagement, owner, folder_path):
    """Scan a single file for security vulnerabilities."""
    file_name = os.path.basename(file_path)
    logging.info(f"Scanning {file_name}...")

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    vuln_collection = db[COLLECTION_NAME]

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            file_content = f.read()

        knowledge_base = setup_knowledge_base()
        llm = get_llm()
        qa_chain = RetrievalQA.from_chain_type(
            llm=llm,
            chain_type="stuff",
            retriever=knowledge_base.as_retriever(),
            verbose=False
        )

        code_chunks = [file_content[i:i + MAX_TOKENS] for i in range(0, len(file_content), MAX_TOKENS)]
        file_findings = []

        for chunk in code_chunks:
            prompt = f"""
            Analyze the following code for security vulnerabilities based on OWASP Top 10.
            Provide structured output in this format:
            Vulnerability: <Name>
            CWE: <CWE SCORE>
            Severity: <Low / Medium / High / Critical>
            Impact: <Risk description>
            Mitigation: <Solution>
            Affected: <File name and line numbers>
            Code Snippet: <Relevant vulnerable code>
            Code:\n{chunk}
            """
            result = qa_chain.invoke({"query": prompt})
            if result and "result" in result:
                findings = extract_relevant_info(result["result"], file_name, engagement, owner, file_content)
                file_findings.extend(findings)

        if file_findings:
            vuln_collection.insert_many(file_findings)

        with progress_lock:
            GLOBAL_SCAN_PROGRESS[folder_path]["scanned"] += 1

        logging.info(f"Completed scanning {file_name}")

    except Exception as e:
        logging.error(f"Error scanning {file_path}: {str(e)}")

    finally:
        client.close()

def worker():
    """Worker thread to process files from the queue."""
    while True:
        try:
            task = scan_queue.get()
            if task is None:
                break
            scan_single_file(*task)
            scan_queue.task_done()
        except Exception as e:
            logging.error(f"Worker error: {e}")

def scan_folder(folder_path, engagement, owner, num_workers=4):
    """Scan an entire folder using multiple threads."""
    source_files = get_source_files(folder_path)
    total_files = len(source_files)

    if not source_files:
        logging.warning(f"No source code files found in {folder_path}")
        return

    with GLOBAL_SCAN_PROGRESS_LOCK:
        GLOBAL_SCAN_PROGRESS[folder_path] = {"total": total_files, "scanned": 0, "status": "running"}

    for file in source_files:
        scan_queue.put((file, engagement, owner, folder_path))

    threads = [threading.Thread(target=worker) for _ in range(num_workers)]
    for thread in threads:
        thread.start()

    scan_queue.join()

    with GLOBAL_SCAN_PROGRESS_LOCK:
        GLOBAL_SCAN_PROGRESS[folder_path]["status"] = "completed"

    for _ in threads:
        scan_queue.put(None)
    
    for thread in threads:
        thread.join()

    logging.info("Scan completed! Findings saved in MongoDB.")
