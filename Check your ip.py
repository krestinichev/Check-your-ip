import ipaddress
import requests
import base64
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def func_abuseipdb(ip):
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {'ipAddress': ip}
        headers = {
            'Accept': 'application/json',
            'Key': 'ENTER_YOUR_API_KEY'
        }
        response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)
        print('https://www.abuseipdb.com/check/' + ip)
        print(
            ' Whitelisted      :', (response.json()['data'])['isWhitelisted'], '\n',
            'AbuseIP_Score    :', (response.json()['data'])['abuseConfidenceScore'], '\n',
            'Usage_Type       :', (response.json()['data'])['usageType'], '\n',
            'ISP              :', (response.json()['data'])['isp'], '\n',
            'Domain           :', (response.json()['data'])['domain'], '\n',
            'Total_Reports    :', (response.json()['data'])['totalReports'], '\n',
            'Last_Reported_At :', (response.json()['data'])['lastReportedAt'], '\n'
        )
    except:
        print('No results, please check URL')


def func_virustotal(ip):
    try:
        url = ("https://www.virustotal.com/api/v3/ip_addresses/" + ip)
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'x-apikey': 'ENTER_YOUR_API_KEY'}
        response = requests.request("GET", url=url, headers=headers, verify=False)
        print('https://www.virustotal.com/gui/ip-address/' + ip)
        print(
            ' Network    :', ((response.json()['data'])['attributes'])['network'], '\n',
            'Country    :', ((response.json()['data'])['attributes'])['country'], '\n',
            'As_owner   :', ((response.json()['data'])['attributes'])['as_owner'], '\n',
            'Malicious  :', (((response.json()['data'])['attributes'])['last_analysis_stats'])['malicious'],
            '(Security vendors flagged this IP address as malicious)', '\n'
        )
    except:
        print('No results, please check URL')


def func_otx(ip):
    try:
        response = requests.get('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip, verify=False)
        print('https://otx.alienvault.com/indicator/ip/' + ip)
        print(
            ' Pulse count : ', (response.json()['pulse_info'])['count'], '\n',
            'Country     : ', response.json()['country_name'], '\n',
            'City        : ', response.json()['city'], '\n'
        )
    except:
        print('No results, please check URL')


def func_IBM(ip):
    try:
        api_key = 'ENTER_YOUR_API_KEY'
        api_pass = 'ENTER_YOUR_API_KEY'
        url = 'https://api.xforce.ibmcloud.com/ipr/' + ip
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Basic ' + (base64.b64encode((api_key + ':' + api_pass).encode('utf-8'))).decode('utf-8'),
        }
        response = requests.request(method='GET', url=url, headers=headers, verify=False)
        print('https://exchange.xforce.ibmcloud.com/ip/' + ip)
        print(
            ' IBM_Score   :', response.json()['score'], '\n',
            'IBM_Reason  :', response.json()['reason'], '\n',
            'Description :', response.json()['reasonDescription'], '\n'
        )
    except:
        print('No results, please check URL')


def func_shodan(ip):
    try:
        api_key = "ENTER_YOUR_API_KEY"
        url = "https://api.shodan.io/shodan/host/" + ip + "?key=" + api_key
        response = requests.request("GET", url, verify=False)
        print('https://www.shodan.io/host/' + ip)
        print(
            ' Open_Port    :', response.json()['ports'], '\n',
            'Orgfnisation :', response.json()['org'], '\n',
            'Domains      :', response.json()['domains'], '\n',
            'Vulns        :', response.json()['vulns'], )
    except:
        print('No results, please check URL')


def check_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print('Incorrect IP')
    else:
        return func_abuseipdb(ip), \
            func_otx(ip), \
            func_virustotal(ip), \
            func_IBM(ip), \
            func_shodan(ip), '\n\n'


while True:
    enter_ip = input('Enter the ip address: ')
    print('\n\n')
    check_ip(enter_ip)
    print('\n\n')
