import requests
import time
from datetime import datetime

url = "http://192.168.71.135"

while True:
    start = time.time()
    dt = datetime.fromtimestamp(start)

    try:
        response = requests.get(url, timeout=5)
        end = time.time()
        rtt_ms = (end - start) * 1000  # 轉成毫秒
        print(f"[✓] {dt.strftime('%d-%m-%Y %H:%M:%S')} | HTTP Status: {response.status_code}\tRTT: {rtt_ms:.2f} ms")

    except requests.exceptions.RequestException as e:
        print(f"[✗] {dt.strftime('%d-%m-%Y %H:%M:%S')} | Request failed: {e}")

    time.sleep(0.5)
