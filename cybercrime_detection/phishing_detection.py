import requests

def check_url(url):
    api_url = f"https://phishstats.info:2096/api/phishing?url={url}"
    response = requests.get(api_url)
    
    if response.ok:
        try:
            data = response.json()
            print(data)  # Print the data to check its structure
            # Check if the response contains the expected field
            if isinstance(data, list) and len(data) > 0 and 'is_phishing' in data[0]:
                return data[0]['is_phishing']
            else:
                print("Unexpected response format.")
                return False
        except ValueError:
            print("Error decoding the response.")
            return False
    else:
        print("Failed to get response from API.")
        return False
# evidence_collector.py