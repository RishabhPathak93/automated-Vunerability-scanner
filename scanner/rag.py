import os
import glob
import time
import json
import multiprocessing
import itertools
import sys
import re
from threading import Thread
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

# MongoDB Configuration
MONGO_URI = ""
DB_NAME = "NewReportingtool"
COLLECTION_NAME = "findings"

# MongoDB Client
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
vuln_collection = db[COLLECTION_NAME]

OUTPUT_FOLDER = "output"
MAX_TOKENS = 1024  # Reduced chunk size

def create_folder_structure():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def get_source_files(folder_path):
    supported_extensions = ["py", "js", "java", "c", "cpp", "go", "php", "rb", "ts", "jsx"]
    files = []
    for ext in supported_extensions:
        files.extend(glob.glob(os.path.join(folder_path, f"**/*.{ext}"), recursive=True))
    return files

@lru_cache(maxsize=1)
def get_llm():
    return Ollama(model="codellama:7b")

def setup_knowledge_base():
    documents = [
        Document(page_content="SQL Injection allows attackers to execute arbitrary SQL queries.", metadata={"source": "OWASP"}),
        Document(page_content="Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.", metadata={"source": "OWASP"}),
        Document(page_content="Use prepared statements to prevent SQL Injection.", metadata={"source": "Best Practices"}),
        Document(page_content="Sanitize user input to prevent XSS attacks.", metadata={"source": "Best Practices"}),
    ]
    embeddings = OllamaEmbeddings(model="codellama")
    return FAISS.from_documents(documents, embeddings)

def extract_vulnerable_function(file_content, snippet):
    pattern = re.compile(r"(\bdef\b|\bfunction\b|\bclass\b).*?\n.*?" + re.escape(snippet) + r".*?\n(?:}|\n)", re.DOTALL)
    match = pattern.search(file_content)
    return match.group(0) if match else snippet

def extract_relevant_info(output, file_name, eng, owner, file_content):
    try:
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
                "engagement": ObjectId(eng),
                "code": 'F-' + str(uuid.uuid4()).replace('-', '')[:8],
                "owner": ObjectId(owner),
                "cvss_vector": "NA",
                "cvss_score": "NA",
                "reference": "NA",
                "assitance": "ASCR",
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
    except Exception as e:
        print(f"⚠️ Error extracting vulnerabilities: {e}")
        return []

def chunk_code(code, chunk_size=MAX_TOKENS):
    return [code[i:i + chunk_size] for i in range(0, len(code), chunk_size)]

def scan_file(file_id, file_path, results_queue, engagement, owner):
    file_name = os.path.basename(file_path)
    print(f"🔍 Scanning {file_name}")

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

        code_chunks = chunk_code(file_content)
        all_findings = []

        for chunk in code_chunks:
            prompt = (
                "Analyze the following code for security vulnerabilities based on OWASP Top 10.\n"
                "Provide structured output in this format:\n"
                "Vulnerability: <Name>\n"
                "CWE: <CWE SCORE>\n"
                "Severity: <Low / Medium / High / Critical>\n"
                "Impact: <Risk description>\n"
                "Mitigation: <Solution>\n"
                "Affected: <File name and line numbers>\n"
                "Code Snippet: <Relevant vulnerable code>\n"
                f"Code:\n{chunk}"
            )

            result = qa_chain.invoke({"query": prompt})
            if result and "result" in result:
                findings = extract_relevant_info(result["result"], file_name, engagement, owner, file_content)
                all_findings.extend(findings)

        if all_findings:
            results_queue.put(all_findings)
    except Exception as e:
        print(f"⚠️ Error scanning {file_path}: {str(e)}")

def scan_folder(folder_path, engagement, owner, num_workers=4):
    source_files = get_source_files(folder_path)
    if not source_files:
        print(f"❌ No source code files found in {folder_path}")
        return

    results_queue = multiprocessing.Queue()
    processes = [multiprocessing.Process(target=scan_file, args=(i, f, results_queue, engagement, owner)) for i, f in enumerate(source_files)]
    
    for p in processes: p.start()
    for p in processes: p.join()
    
    final_results = []
    while not results_queue.empty():
        final_results.extend(results_queue.get())
    
    if final_results:
        vuln_collection.insert_many(final_results)
    print("✅ Scan completed! Results saved.")
