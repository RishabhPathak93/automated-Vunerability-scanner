from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .rag import scan_folder, GLOBAL_SCAN_PROGRESS, GLOBAL_SCAN_PROGRESS_LOCK
import threading

class ScanView(APIView):
    def post(self, request):
        folder_path = request.data.get("folder_path")
        engagement = request.data.get("engagement")
        owner = request.data.get("owner")

        if not folder_path or not engagement or not owner:
            return Response({"error": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

        scan_thread = threading.Thread(target=scan_folder, args=(folder_path, engagement, owner))
        scan_thread.start()

        return Response({"message": "Scan started successfully.", "folder_path": folder_path}, status=status.HTTP_202_ACCEPTED)


class ScanProgressView(APIView):
    def get(self, request):
        folder_path = request.query_params.get("folder_path")

        if not folder_path:
            return Response({"error": "Missing folder_path parameter."}, status=status.HTTP_400_BAD_REQUEST)

        with GLOBAL_SCAN_PROGRESS_LOCK:
            progress = GLOBAL_SCAN_PROGRESS.get(folder_path)

        if progress:
            return Response(progress, status=status.HTTP_200_OK)

        return Response({"error": "No scan progress found for the given folder."}, status=status.HTTP_404_NOT_FOUND)


class ScanResultsView(APIView):
    def get(self, request):
        folder_path = request.query_params.get("folder_path")

        if not folder_path:
            return Response({"error": "Missing folder_path parameter."}, status=status.HTTP_400_BAD_REQUEST)

        with GLOBAL_SCAN_PROGRESS_LOCK:
            progress = GLOBAL_SCAN_PROGRESS.get(folder_path)

        if not progress or progress["status"] != "completed":
            return Response({"error": "Scan not completed or invalid folder path."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Scan results available.", "folder_path": folder_path}, status=status.HTTP_200_OK)
