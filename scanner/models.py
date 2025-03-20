from django.db import models

class ScanResult(models.Model):
    file_name = models.CharField(max_length=255)
    vulnerability = models.CharField(max_length=255)
    cwe = models.CharField(max_length=50)
    severity = models.CharField(max_length=50)
    impact = models.TextField()
    mitigation = models.TextField()
    affected = models.TextField()
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file_name} - {self.vulnerability} ({self.severity})"
