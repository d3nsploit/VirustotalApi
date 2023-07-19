import requests
import json
import ipaddress
import validators
import base64

def check_url(ioc,headers):
    url_encode = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")

    url = "https://www.virustotal.com/api/v3/urls/"+url_encode
    response = requests.get(url, headers=headers)

    result=response.text

    jsons=json.loads(result)
    ioc=ioc.strip('\n')
    try:
        reported_harmless=jsons["data"]["attributes"]["last_analysis_stats"]["harmless"]
        reported_malicious=jsons["data"]["attributes"]["last_analysis_stats"]["malicious"]
        reported_suspicious=jsons["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        reported_undetected=jsons["data"]["attributes"]["last_analysis_stats"]["undetected"]
        print("ioc:{} harmless:{} malicious:{} suspicious:{} undetected:{}".format(ioc,reported_harmless,reported_malicious,reported_suspicious,reported_undetected))

    except:
        print("URL {} Not Matches Found".format(ioc))


def check_hashes(ioc,headers):
    url = "https://www.virustotal.com/api/v3/files/"+ioc
    response = requests.get(url, headers=headers)

    result=response.text
    ioc=ioc.strip('\n')

    jsons=json.loads(result)
    try:

        # hash_md5=jsons["data"]["attributes"]["md5"]
        # hash_sha1=jsons["data"]["attributes"]["sha1"]
        # hash_sha256=jsons["data"]["attributes"]["sha256"]
        reported_harmless=jsons["data"]["attributes"]["last_analysis_stats"]["harmless"]
        reported_malicious=jsons["data"]["attributes"]["last_analysis_stats"]["malicious"]
        reported_suspicious=jsons["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        reported_undetected=jsons["data"]["attributes"]["last_analysis_stats"]["undetected"]
        print("ioc:{} harmless:{} malicious:{} suspicious:{} undetected:{}".format(ioc,reported_harmless,reported_malicious,reported_suspicious,reported_undetected))
    except:
        print("Hash {} Not Matches Found".format(ioc))


def check_domain(ioc,headers):
    url = "https://www.virustotal.com/api/v3/domains/"+ioc
    response = requests.get(url, headers=headers)

    result=response.text
    ioc=ioc.strip('\n')

    jsons=json.loads(result)

    try:
        reported_harmless=jsons["data"]["attributes"]["last_analysis_stats"]["harmless"]
        reported_malicious=jsons["data"]["attributes"]["last_analysis_stats"]["malicious"]
        reported_suspicious=jsons["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        reported_undetected=jsons["data"]["attributes"]["last_analysis_stats"]["undetected"]
        print("ioc:{} harmless:{} malicious:{} suspicious:{} undetected:{}".format(ioc,reported_harmless,reported_malicious,reported_suspicious,reported_undetected))
    except:
        print("Domain {} Not Matches Found".format(ioc))

def check_ip(ioc,headers):
    url = "https://www.virustotal.com/api/v3/ip_addresses/"+ioc
    response = requests.get(url, headers=headers)
    ioc=ioc.strip('\n')

    result=response.text

    jsons=json.loads(result)

    try:
        reported_id=jsons["data"]["id"]
        reported_harmless=jsons["data"]["attributes"]["last_analysis_stats"]["harmless"]
        reported_malicious=jsons["data"]["attributes"]["last_analysis_stats"]["malicious"]
        reported_suspicious=jsons["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        reported_undetected=jsons["data"]["attributes"]["last_analysis_stats"]["undetected"]
        print("ioc:{} harmless:{} malicious:{} suspicious:{} undetected:{}".format(ioc,reported_harmless,reported_malicious,reported_suspicious,reported_undetected))
    except:
        print("IP Address {} Not Matches Found".format(ioc))

headers = {
    "accept": "application/json",
    "x-apikey": "7ed54afe56f808850ca99bd0a68223144acf5ace4a4c3af72022b748b3ae7312"
}

f = open("demofile.txt", "r")
for indicator in f:
    if indicator.startswith('http://') or indicator.startswith('https://'):
        check_url(indicator,headers)
    else:
        try:  
            ip_obj = ipaddress.ip_address(indicator)  
            check_ip(indicator,headers) 
        except:  
            if validators.domain(indicator):
                check_domain(indicator,headers)
            else:
                check_hashes(indicator,headers)
            
