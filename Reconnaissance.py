from urllib.parse import urlparse
import subprocess
import socket
import requests
import ssl

def prompt_user():
    user_choice= input("Please select an option [i for IP  or u for URL]: ")
    if user_choice == "i":
         print("Welcome! Please enter an IP address:")
         target= input()
         return target
    elif user_choice == "u":
        print("Welcome! Please enter an URL:")
        target = input()
        return target

   
def get_IP(url):
    try:
        if "https://" in url:
            url = url.replace("https://", "").replace("http://", "")
            ip_address = socket.gethostbyname(url)
            return ip_address
        else:
            ip_address = socket.gethostbyname(url)
            return ip_address

    except socket.gaierror:
        return None
    
def get_Server(target):
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        response = requests.get(target).headers
        response = requests.head(target)
        server_type = response.headers.get('Server', 'N/A')
        if 'Apache' in server_type:
            print("Apache")
        elif 'WordProcess' in server_type:
            print("WordProcess")
        else:
            print("Unknown")
    except requests.exceptions.RequestException:
        print(f"Unable to fetch server information for {target}\n")

def check_vulnerability(target):
    nmap_command = f"nmap -p80 --script http-stored-xss {target}"
    nmap_process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, _ = nmap_process.communicate()

    if b"VULNERABLE" in output:
        return "Vulnerable"
    else:
        return "Not Vulnerable"

def create_report(target, ip_address, server_type, xss_vulnerability):
    report_filename = f"Reconnaissance_report_{target}.txt"
    with open(report_filename, 'w') as report_file:
        report_file.write(f"Target: {target}\n")
        report_file.write(f"IP Address: {ip_address}\n")
        report_file.write(f"Web Server Type: {server_type}\n")
        report_file.write(f"HTTP Stored XSS Vulnerability: {xss_vulnerability}\n")

def process_single_target():
    try:
        url = prompt_user()
        target = get_IP(url)
        server_type = get_Server(url)
        xss_vulnerability = check_vulnerability(target)
        print(target)
        print(server_type)
        print(xss_vulnerability)
        create_report(url, target, server_type, xss_vulnerability)
    except:
        print(f"Invalid IP address or URL: {target}")
    

def process_batch_targets():
    print("Please enter the path to the file containing the list of targets:")
    file_path = input()
    with open(file_path, 'r') as targets_file:
        for target in targets_file:
            target = target.strip()
            ip_address = get_IP(target)
            if ip_address:
                server_type = get_IP(target)
                xss_vulnerability = check_vulnerability(target)
                create_report(target, ip_address, server_type, xss_vulnerability)
            else:
                print(f"Invalid IP address or URL: {target}")

def main():
    print("Proverbs 10:2 Treasures gained by wickedness do not profit, but righteousness delivers from death. With that said, remember the cybercrime act.")
    print("Do you want to process a single target or batch targets? Enter 's' for single  or 'b' for batch :")
    user_choice = input()
    if user_choice == 's':
        process_single_target()
    elif user_choice== 'b':
        process_batch_targets()
    else:
        print("Invalid choice. Please enter 'single' or 'batch'.")


if __name__ == '__main__':
    main()
    
    

    




