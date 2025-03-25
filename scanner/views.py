from django.http import JsonResponse
from django.views import View
import json
import threading
import os
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .rag import scan_folder  

# Store scan progress globally (or use a database)
scan_progress = {}

@method_decorator(csrf_exempt, name='dispatch')
class ScanView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            folder_path = data.get("folder_path")
            engagement = data.get("engagement")
            owner = data.get("owner")
            num_workers = data.get("num_workers", 4)

            if not folder_path or not engagement or not owner:
                return JsonResponse({"error": "Missing required fields"}, status=400)

            os.makedirs("./output/", exist_ok=True)

            # Initialize progress tracking
            scan_progress[folder_path] = {"scanned": 0, "total": 1}  # Default values to prevent division by zero
            
            thread = threading.Thread(target=run_scan, args=(folder_path, engagement, owner, num_workers))
            thread.start()

            return JsonResponse({"message": "Scan started successfully"}, status=202)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

def run_scan(folder_path, engagement, owner, num_workers):
    print(f"🚀 Scan started for: {folder_path}")

    if not os.path.exists(folder_path):
        print(f"❌ ERROR: Folder '{folder_path}' does not exist!")
        return

    print(f"✅ Scanning {folder_path} with {num_workers} workers for {engagement} owned by {owner}")

    # Call the scan function while passing the progress tracking dictionary
    scan_folder(folder_path, engagement, owner, num_workers, scan_progress)

class ScanProgressView(View):
    def get(self, request, *args, **kwargs):
        folder_path = request.GET.get("folder_path")
        if not folder_path or folder_path not in scan_progress:
            return JsonResponse({"error": "Invalid or missing folder path"}, status=400)

        progress = scan_progress[folder_path]
        percentage = (progress["scanned"] / progress["total"]) * 100 if progress["total"] > 0 else 0

        return JsonResponse({"progress": round(percentage, 2), "scanned": progress["scanned"], "total": progress["total"]})
class ScanResultsView(View):
    def get(self, request, *args, **kwargs):
        return JsonResponse({"message": "Scan results not implemented yet"}, status=200)
