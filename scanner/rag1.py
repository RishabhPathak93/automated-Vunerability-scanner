import os
import glob
import uuid
import logging
import threading
import queue
import json
from datetime import datetime
from bson import ObjectId
from pymongo import MongoClient
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import OllamaEmbeddings
from langchain_core.documents import Document
from langchain.chains import RetrievalQA
from langchain_community.llms import Ollama
from threading import Lock
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Global scan progress tracking
GLOBAL_SCAN_PROGRESS = {}
GLOBAL_SCAN_PROGRESS_LOCK = Lock()

# MongoDB Configuration
MONGO_URI = "mongodb+srv://astraaccess:hbf3bcyZhcb3ycb@astrart.ccqas.mongodb.net/NewReportingtool?retryWrites=true&w=majority&appName=AstraRT"
DB_NAME = "NewReportingtool"
COLLECTION_NAME = "findings"
MAX_TOKENS = 8000  # Max tokens per request

# Queue for managing scan tasks
scan_queue = queue.Queue()
progress_lock = threading.Lock()

def get_source_files(folder_path):
    supported_extensions = ["py", "js", "java", "c", "cpp", "go", "php", "rb", "ts", "jsx", "html", "css", "scss", "tsx"]
    return [f for ext in supported_extensions for f in glob.glob(os.path.join(folder_path, f"**/*.{ext}"), recursive=True)]

@lru_cache(maxsize=1)
def get_llm():
    return Ollama(model="codellama:13b")

def setup_knowledge_base():
    documents = [
        Document(page_content="SQL Injection allows attackers to execute arbitrary SQL queries.", metadata={"source": "OWASP"}),
        Document(page_content="Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.", metadata={"source": "OWASP"}),
        Document(page_content="Use prepared statements to prevent SQL Injection.", metadata={"source": "Best Practices"}),
        Document(page_content="Sanitize user input to prevent XSS attacks.", metadata={"source": "Best Practices"}),
    ]
    embeddings = OllamaEmbeddings(model="codellama")
    return FAISS.from_documents(documents, embeddings)

def get_relevant_context(file_content):
    knowledge_base = setup_knowledge_base()  
    retriever = knowledge_base.as_retriever()
    query = f"Security vulnerabilities in code: {file_content[:500]}"
    result = retriever.invoke(query)
    return "\n".join([doc.page_content for doc in result])  

def clean_json_response(response):
    import re

    response = response.strip()

    # Remove surrounding Markdown JSON markers
    if response.startswith("```json"):
        response = response[len("```json"):].strip()
    if response.endswith("```"):
        response = response[:-3].strip()

    # Try to find the first JSON object
    start_index = response.find("{")
    if start_index != -1:
        response = response[start_index:]

    # Replace curly quotes and newlines
    response = response.replace('“', '"').replace('”', '"').replace('\n', '')
    response = response.replace("’", "'")

    # Escape any inner double quotes inside string values safely
    def fix_json_strings(match):
        key, val = match.groups()
        # Escape only inner double quotes (ignore the ones wrapping the value)
        val_fixed = val.replace('\\', '\\\\').replace('"', r'\"')
        return f'"{key}": "{val_fixed}"'

    # Use regex to fix "key": "string with possibly bad quotes"
    string_value_pattern = re.compile(r'"(\w+)"\s*:\s*"((?:[^"\\]|\\.)*?)"')
    safe_json = string_value_pattern.sub(fix_json_strings, response)

    try:
        return json.loads(safe_json)
    except json.JSONDecodeError as e:
        logging.error(f"LLM response is not valid JSON: {e}\nRaw output: {response}")
        return {"vulnerabilities": []}


def analyze_code_with_context(file_content, file_name):
    context = get_relevant_context(file_content)
    
    prompt = f"""
    Analyze the following code for security vulnerabilities based on OWASP Top 10.
    The context documents explain security best practices.

    Context:\n{context}

    Code:\n{file_content}

    Strictly Return ONLY a JSON object in the following format:

    {{
        "vulnerabilities": [
            {{
                "title": "Vulnerability Name",
                "CWE_ID": "CWE-XXX",
                "severity": "Low | Medium | High | Critical",
                "affected_lines": [line_numbers],
                "file_name": "{file_name}",
                "description": "Description of Title",
                "mitigation": "How to fix the issue",
                "impact": "Impact of the Vulnerability"
            }}
        ]
    }}

    Do NOT include any explanations, just return the JSON object.
    """

    llm = get_llm()
    result = llm.invoke(prompt)

    logging.info(f"Raw LLM Output: {result}")
    return clean_json_response(result)

def extract_code(fn, lnums): # fn - filename, lnums - line_numbers array
    try:
        minn = min(lnums) - 1;maxx = max(lnums);
        code = "";count = 0;
        print("Fetching Line "+str(minn)+"-"+str(maxx))
        with open(fn, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                count += 1
                if(minn <= count):
                    code += str(line)
                if(maxx == count):
                    break;
        return code
    except:
        pass

def scan_single_file(file_path, engagement, owner, folder_path):
    file_name = os.path.basename(file_path)
    logging.info(f"Scanning {file_name}...")

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    vuln_collection = db[COLLECTION_NAME]

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            file_content = f.read()

        result = analyze_code_with_context(file_content, file_name)
        
        vulnerabilities = result.get("vulnerabilities", [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                vuln["code"] = "F-" + str(uuid.uuid4()).replace("-", "")[:8]
                vuln["owner"] = ObjectId(owner)
                vuln["cvss_vector"] = "NA"
                vuln["cvss_score"] = "NA"
                vuln["reference"] = "NA"
                vuln["assistance"] = "ASCR"
                vuln["engagement"] = ObjectId(engagement)
                vuln["rpoc"] = "NA"
                vuln["rpocdesc"] = "NA"
                vuln["under_reval"] = False
                vuln["desc"] = vuln.pop("description")
                vuln["cwe"] = vuln.pop("CWE_ID")
                vuln["popdesc"] = "[]"
                vuln["pocpic"] = extract_code(file_path, vuln["affected_lines"])
                vuln["security_risk"] = vuln.pop("impact")
                vuln["affected_url"] = f"{vuln.pop('file_name')} \nLine Number(s) : {', '.join(map(str, vuln.pop('affected_lines')))}"
                vuln["approved"] = False
                vuln["status"] = "OPEN"
                vuln["deleted"] = False
                vuln["createdAt"] = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
 
            vuln_collection.insert_many(vulnerabilities)
            
        with progress_lock:
            GLOBAL_SCAN_PROGRESS[folder_path]["scanned"] += 1

        logging.info(f"Completed scanning {file_name}")

    except Exception as e:
        logging.error(f"Error scanning {file_path}: {str(e)}")

    finally:
        client.close()

def worker():
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
    logging.info("Scan completed! Findings saved in MongoDB.")
