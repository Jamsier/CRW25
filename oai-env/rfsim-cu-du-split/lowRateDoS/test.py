import time
import requests
from requests.adapters import HTTPAdapter
import socket
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool

class SourceIPHTTPConnection(HTTPConnection):
    def __init__(self, *args, source_address=None, **kwargs):
        self.source_address = source_address
        super().__init__(*args, **kwargs)

    def connect(self):
        sock = socket.create_connection(
            (self.host, self.port),
            self.timeout,
            source_address=self.source_address
        )
        self.sock = sock

class SourceIPHTTPConnectionPool(HTTPConnectionPool):
    def __init__(self, *args, source_address=None, **kwargs):
        self.source_address = source_address
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        return SourceIPHTTPConnection(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
            source_address=self.source_address
        )

class SourceIPAdapter(HTTPAdapter):
    def __init__(self, source_ip, **kwargs):
        self.source_ip = source_ip
        super().__init__(**kwargs)

    def get_connection(self, url, proxies=None):
        pool = super().get_connection(url, proxies)
        pool_cls = type(pool)
        return pool_cls(pool.host, pool.port, source_address=(self.source_ip, 0))

def test_rtt(url, source_ip):
    session = requests.Session()
    adapter = SourceIPAdapter(source_ip)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    rtts = []
    i=0
    while True:
        try:
            start = time.time()
            response = session.get(url, timeout=5)
            end = time.time()
            rtt = (end - start) * 1000
            rtts.append(rtt)
            print(f"[{i+1}] RTT: {rtt:.2f} ms (HTTP {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[{i+1}] Error: {e}")
        time.sleep(1)
    if rtts:
        avg = sum(rtts) / len(rtts)
        print(f"\n平均 RTT（成功 {len(rtts)} 次）: {avg:.2f} ms")

if __name__ == "__main__":
    test_url = "http://192.168.71.135"
    source_ip = "10.0.0.2"  # 換成你想指定的 source IP
    while True:
        test_rtt(test_url, source_ip)
