from django.urls import path
from .views import ScanView as ScanFolderView, ScanResultsView

urlpatterns = [
    path("scan/", ScanFolderView.as_view(), name="scan-folder"),
    path("results/", ScanResultsView.as_view(), name="scan-results"),
]
