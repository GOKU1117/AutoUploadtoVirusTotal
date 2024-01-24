import requests
import time
import os

# For test use
API_KEYS = [
    'API KEY 1',
    'API KEY 2',
    'API KEY 3'
]

def check_ip_malicious(ip_address, api_key):
    url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip_address
    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            if 'data' in result and 'attributes' in result['data']:
                attributes = result['data']['attributes']
                if 'last_analysis_stats' in attributes:
                    stats = attributes['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    undetected = stats.get('undetected', 0)

                    if malicious > 0 or suspicious > 0:
                        return f"The IP address {ip_address} is potentially malicious."
                    elif undetected > 0:
                        return f"The IP address {ip_address} has not been detected as malicious."
                    else:
                        return f"The IP address {ip_address} has no available information."
                else:
                    return f"No analysis stats available for the IP address {ip_address}."
            else:
                return f"No information available for the IP address {ip_address}."
        elif response.status_code == 404:
            return f"Error 404: IP address {ip_address} not found in Virustotal."
        elif response.status_code == 401:
            print("API Not Access")
            return f"Error 401: Unauthorized access to Virustotal API."

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Input scan ip file
input_file_path = 'INPUT FILE PATH'
# Output result file
output_file_path = 'OUTPUT FILE PATH'

with open(input_file_path, 'r', encoding="ISO-8859-1") as txtfile:
    lines = txtfile.readlines()

api_key_index = 0 

with open(output_file_path, 'w', encoding='UTF-8') as outputfile:
    for idx, line in enumerate(lines):
        ip_address = line.strip()
        api_key = API_KEYS[api_key_index]

        result = check_ip_malicious(ip_address, api_key)

        # Handle the case where result is None
        if result is not None and "potentially" in result:
            outputfile.write(f"{ip_address}: {result}\n")
            print(result)
        elif result is not None:
            print(result)
        else:
            print(f"Error occurred for IP address: {ip_address}")

        time.sleep(10)

        # Check if we have processed 498 IPs with the current API key
        if (idx + 1) % 498 == 0:
            api_key_index = (api_key_index + 1) % len(API_KEYS)  
            print(f'Switched to API key {api_key_index + 1}')
