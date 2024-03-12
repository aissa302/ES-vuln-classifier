from bs4 import BeautifulSoup
import requests
from tqdm import tqdm
import os

## Send a GET request to the ZDI website
#with open("zdi_links.txt", "w+") as f:
#    for year in tqdm(range(2005, 2025)):
#        response = requests.get(f'https://www.zerodayinitiative.com/advisories/published/{year}/')
#
#        soup = BeautifulSoup(response.text, 'html.parser')
#
#        # Find all <td> tags with class "sort-td"
#        for td_tag in soup.find_all('td', class_='sort-td'):
#            # Get the text content of the <td> tag
#            zdi_id = td_tag.text.strip()
#            # Find the <a> tag within the <td> tag
#            link_tag = td_tag.find('a')
#            if link_tag:
#                # Get the href attribute value
#                link = link_tag['href']
#                # Write the link in the desired format to the text file
#                f.write(f"https://www.zerodayinitiative.com{link}\n")


import pandas as pd
#from bs4 import BeautifulSoup

# Function to parse HTML and extract data
def parse_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract ZDI-ID and ZDI-CAN from the <h3> tag
    h3_contents = soup.find('h3').contents
    zdi_id = h3_contents[0].strip()
    zdi_can = h3_contents[2].strip() 
    
    CVE =  soup.find('a', href=lambda x: x and "CVE" in x)
    if CVE is not None:
        CVE = CVE.text.strip()
    else:
        CVE = "N/A"
    CVSS = soup.find('a', href=lambda x: x and "cvss" in x)
    if CVSS is not None:
        CVSS = CVSS.text.strip()
    else:
        CVSS = "N/A"
    AFFECTED_VENDORS = soup.find('td', string='AFFECTED VENDORS').find_next_sibling('td')
    if AFFECTED_VENDORS is not None:
        AFFECTED_VENDORS = AFFECTED_VENDORS.text.strip()
    else:
        AFFECTED_VENDORS = "N/A"
    AFFECTED = soup.find('td', string='AFFECTED PRODUCTS').find_next_sibling('td')
    if AFFECTED is not None:
        AFFECTED = AFFECTED.text.strip()
    else:
        AFFECTED = "N/A"
    VULNERABILITY = soup.find('td', string='VULNERABILITY DETAILS').find_next_sibling('td')
    if VULNERABILITY is not None:
        VULNERABILITY = VULNERABILITY.text.strip()
    else:
        VULNERABILITY = "N/A"
    ADDITIONAL = soup.find('td', string='ADDITIONAL DETAILS').find_next_sibling('td')
    if ADDITIONAL is not None:
        ADDITIONAL = ADDITIONAL.text.strip()
    else:
        ADDITIONAL = "N/A"
    ZDI = zdi_id.strip(),
    ZDI = zdi_can.strip(),

    data = {
        'CVE ID': CVE,
        'CVSS SCORE': CVSS,
        'AFFECTED VENDORS': AFFECTED_VENDORS,
        'AFFECTED PRODUCTS': AFFECTED.strip(),
        'VULNERABILITY DETAILS': VULNERABILITY,
        'ADDITIONAL DETAILS': ADDITIONAL,
        'ZDI-ID': zdi_id.strip(),
        'ZDI-CAN': zdi_can.strip(),
    }

    return data

# Example usage
with open("zdi_links.txt", "r") as f:
    zdi_links = f.readlines()

    # Send a GET request to the first link
    for link in tqdm(zdi_links):
        response = requests.get(link.strip())
        html_content = response.text

        # Parse the HTML content
        parsed_data = parse_html(html_content)
        # Appending the data to a CSV file
        df = pd.DataFrame([parsed_data])
        df = pd.DataFrame([parsed_data])
        if not os.path.exists('../data/zdi-data/zdi_data.csv'):
            df.to_csv('../data/zdi-data/zdi_data.csv', mode='w', index=False, header=True)
        else:
            df.to_csv('../data/zdi-data/zdi_data.csv', mode='a', index=False, header=False)
