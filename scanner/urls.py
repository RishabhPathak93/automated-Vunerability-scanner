from django.urls import path
from .views import ScanView, ScanResultsView, ScanProgressView

urlpatterns = [
    path("scan/", ScanView.as_view(), name="scan-folder"),
    path("results/", ScanResultsView.as_view(), name="scan-results"),
    path("progress/", ScanProgressView.as_view(), name="scan-progress"),
]

