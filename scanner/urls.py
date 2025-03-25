from django.urls import path
from .views import ScanView as ScanFolderView, ScanResultsView, ScanProgressView

urlpatterns = [
    path("scan/", ScanFolderView.as_view(), name="scan-folder"),
    path("results/", ScanResultsView.as_view(), name="scan-results"),
    path("progress/", ScanProgressView.as_view(), name="scan-progress"),
]
