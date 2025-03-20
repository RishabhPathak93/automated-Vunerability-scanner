import os
import glob
import argparse
import time
import json
import multiprocessing
import itertools
import sys
import re
from threading import Thread
from functools import lru_cache
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import OllamaEmbeddings
from langchain_core.documents import Document
from langchain.chains import RetrievalQA
from langchain_community.llms import Ollama
from pymongo import MongoClient
import uuid
from datetime import datetime

from bson import ObjectId

# MongoDB Configuration
MONGO_URI = "your url"
DB_NAME = "NewReportingtool"
COLLECTION_NAME = "findings"

# MongoDB Client
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
vuln_collection = db[COLLECTION_NAME]

# Folder structure
OUTPUT_FOLDER = "output.json"
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "output.json")
MAX_TOKENS = 1024  # Reduced chunk size for better processing

def create_folder_structure():
    """Create the output folder if it doesn't exist."""
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def animate_scanning(file_id, file_name, file_scanning_complete):
    """Display a scanning animation while the file is being processed."""
    for c in itertools.cycle(["|", "/", "-", "\\"]):
        if file_scanning_complete[file_id]:
            break
        sys.stdout.write(f"\r🔍 Scanning {file_name} {c}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write(f"\r✅ Scanning {file_name} Complete! 🎯\n")

def get_source_files(folder_path):
    """Get all source code file paths."""
    supported_extensions = ["py", "js", "java", "c", "cpp", "go", "php", "rb", "ts", "jsx"]
    files = []
    for ext in supported_extensions:
        files.extend(glob.glob(os.path.join(folder_path, f"**/*.{ext}"), recursive=True))
    return files

@lru_cache(maxsize=1)
def get_llm():
    """Load the LLM model only once to reduce memory usage."""
    return Ollama(model="codellama:7b")

def setup_knowledge_base():
    """Set up a knowledge base for RAG using FAISS and Ollama embeddings."""
    documents = [
        Document(page_content="SQL Injection allows attackers to execute arbitrary SQL queries.", metadata={"source": "OWASP"}),
        Document(page_content="Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.", metadata={"source": "OWASP"}),
        Document(page_content="Use prepared statements to prevent SQL Injection.", metadata={"source": "Best Practices"}),
        Document(page_content="Sanitize user input to prevent XSS attacks.", metadata={"source": "Best Practices"}),
    ]
    
    embeddings = OllamaEmbeddings(model="codellama")
    knowledge_base = FAISS.from_documents(documents, embeddings)
    return knowledge_base

def extract_relevant_info(output, file_name, eng, owner):
    """Extracts vulnerability details from LLM output and formats it into JSON."""
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
            r"Affected:\s*(.*?)\s*(?:\n|$)",  
            re.DOTALL
        )

        matches = pattern.findall(output)
        for match in matches:
            vulnerabilities.append({
                "title": match[0].strip(),
                "CWE": match[1].strip(),
                "severity": match[2].strip(),
                "impact": match[3].strip(),
                "mitigation": match[4].strip(),
                "affected": f"{file_name} - {match[5].strip()}",
                "engagement": ObjectId(eng),
                "code": 'F-'+str(uuid.uuid4()).replace('-', '')[:8],
                "owner": ObjectId(owner),
                "cvss_vector": "NA",
                "cvss_score": "NA",
                "reference": "NA",
                "assitance": "ASCR",
                "pocpic":"[]",
                "pocdesc":"[]",
                "rpoc":"[]",
                "rpocdesc":"[]",
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
    """Splits code into smaller chunks for analysis."""
    return [code[i:i + chunk_size] for i in range(0, len(code), chunk_size)]

def scan_file(file_id, file_path, file_scanning_complete, results, engagement, owner):
    """Scan a file for vulnerabilities using the RAG approach."""
    file_name = os.path.basename(file_path)
    file_scanning_complete[file_id] = False
    animation_thread = Thread(target=animate_scanning, args=(file_id, file_name, file_scanning_complete))
    animation_thread.start()
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            code_content = file.read()
        
        knowledge_base = setup_knowledge_base()
        llm = get_llm()
        
        qa_chain = RetrievalQA.from_chain_type(
            llm=llm,
            chain_type="stuff",
            retriever=knowledge_base.as_retriever(),
            verbose=False
        )

        code_chunks = chunk_code(code_content)
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
                f"Code:\n{chunk}"
            )

            result = qa_chain.invoke({"query": prompt})
            print(f"\nRAW OUTPUT for {file_name}:\n", result.get("result", "No valid result"))

            if result and "result" in result:
                findings = extract_relevant_info(result["result"], file_name, engagement, owner)
                all_findings.extend(findings)

        if all_findings:
            results.extend(all_findings)
        else:
            print(f"⚠️ No vulnerabilities detected in {file_path}")

    except Exception as e:
        print(f"⚠️ Error scanning {file_path}: {str(e)}")
    
    file_scanning_complete[file_id] = True
    animation_thread.join()

def scan_folder(folder_path, engagement, owner, num_workers=4):
    """Scan all source code files in the folder and save findings."""
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    source_files = get_source_files(folder_path)

    if not source_files:
        print(f"❌ No source code files found in {folder_path}")
        return

    manager = multiprocessing.Manager()
    file_scanning_complete = manager.dict()
    results = manager.list()

    with multiprocessing.Pool(processes=num_workers) as pool:
        tasks = []
        for file_id, file_path in enumerate(source_files):
            file_scanning_complete[file_id] = False
            task = pool.apply_async(scan_file, (file_id, file_path, file_scanning_complete, results, engagement, owner))
            tasks.append(task)

        for task in tasks:
            task.wait()

    final_results = list(results)

    # with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    #     json.dump(final_results, f, indent=4)
    print(final_results)
    vuln_collection.insert_many(list(final_results))


    print(f"✅ Scan completed! Results saved in {OUTPUT_FILE}")




def run_scan(folder_path, engagement, owner, num_workers):
    print(f"🚀 Scan started for: {folder_path}")
    
    if not os.path.exists(folder_path):
        print(f"❌ ERROR: Folder '{folder_path}' does not exist!")
        return

    # Your scanning logic here
    print(f"✅ Scanning {folder_path} with {num_workers} workers for {engagement} owned by {owner}")
    
    
    

def main(folder_path, num_workers):
    """Run the security scan."""
    create_folder_structure()
    scan_folder(folder_path, num_workers)

if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)  # Ensures compatibility across OS
    parser = argparse.ArgumentParser(description="Secure Code Review Bot with RAG Approach")
    parser.add_argument("folder_path", help="Path to the folder containing source code")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel processes (default: 4)")
    args = parser.parse_args()
    main(args.folder_path, args.workers)
