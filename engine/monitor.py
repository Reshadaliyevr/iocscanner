from engine.api_monitor import APIMonitorQueue

api_monitor = APIMonitorQueue({
    "virustotal": 4,
    "abuseipdb": 30,
    "urlscan": 60,
    "hybrid": 5
})
