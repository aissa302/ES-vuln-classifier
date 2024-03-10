from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from tqdm import tqdm
#from es_vuln_extraction import tools
import requests
import csv
import pandas as pd

tqdm.pandas()

# Initialize a session
session = requests.Session()

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
}
# Headless browse
#options = webdriver.ChromeOptions()
#options.add_argument('--headless')
# Function to extract details from an HTML page
def extract_details(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    var_id = soup.find('h4', text='ID').find_next_sibling('div').p.get_text(strip=True)
    cve_id = soup.find('h4', text='CVE').find_next_sibling('div').p.get_text(strip=True)
    title = soup.find('h4', text='TITLE').find_next_sibling('div').p.get_text(strip=True)
    description = soup.find('h4', text='DESCRIPTION').find_next_sibling('div').p.get_text(strip=True)
    category = soup.find('small', text='category:').find_next('td').get_text(strip=True)
    vendor = soup.find('small', text='vendor:').find_next('td').get_text(strip=True)
    model = soup.find('small', text='model:').find_next('td').get_text(strip=True)
    version = soup.find('small', text='version:').find_next('td').get_text(strip=True)
    patch_title = soup.find('small', text='title:').find_next('td').get_text(strip=True)
    patch_url = soup.find('small', text='url:').find_next('td').get_text(strip=True)
    sources = ', '.join([source.get_text(strip=True) for source in soup.select('div:contains("SOURCES") + div table td:nth-of-type(2)')])
    references = ', '.join([ref.get_text(strip=True) for ref in soup.select('div:contains("REFERENCES") + div table td:nth-of-type(2)')])

    return [var_id, cve_id, title, description, category, vendor, model, version, sources, references, patch_title, patch_url]

# Set up the Selenium WebDriver
#driver = webdriver.Chrome("../driver/chromedriver", options=options)  # Replace with the appropriate driver for your browser
with open('../data/VarIoT_data/vulnerabilities.csv', 'w', newline='') as file:
    writer = csv.writer(file)
     # Write the header row
    writer.writerow(['VAR ID', 'CVE ID', 'Title', 'Description', 'Category', 'Vendor', 'Model', 'Version', 'Sources', 'References', 'Patch Title', 'Patch URL'])
# Define CSV file to write to
#with open('../data/VarIoT_data/var_links.csv', 'w', newline='') as file:
 #   writer = csv.writer(file)
    # Write the header row
 #   writer.writerow(['VAR Details Link'])
    #for page_next in tqdm(range(1, 1991)):
        # Load the webpage
        #res = session.get(f"https://www.variotdbs.pl/vulns/?page={page_next}&amp;", headers=header)

        # Click the link
    links = pd.read_csv('../data/VarIoT_data/var_links.csv')
    for link in tqdm(links['VAR Details Link']):
        res = session.get(link, headers=header)
    # Extract the updated HTML content
    #html_content = driver.page_source
        html_content = res.text
        data = extract_details(html_content)
    
        # Append the extracted data to the CSV file
        with open('/mnt/data/vulnerabilities.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(data)
        # Assuming all relevant data is within table rows (<tr>)
        #rows = soup.find_all('tr')

        #base_url = "https://www.variotdbs.pl"
        #for row in rows:
        #    # Find all <a> tags in the row
        #    a_tags = row.find_all('a', href=True)
        #    # Filter out <a> tags that have 'href' containing "/vuln/VAR-"
        #    var_links = [a['href'] for a in a_tags if '/vuln/VAR-' in a['href']]
        #    # Prepend base URL to each VAR link and write to CSV
        #    for var_link in var_links:
        #        full_var_link = base_url + var_link
        #        writer.writerow([full_var_link])

# Output file path
#print("Data has been written to var_links.csv")
        #soup = BeautifulSoup(html_content, 'html.parser')
#
        ## Assuming all relevant data is within table rows (<tr>)
        #rows = soup.find_all('tr')
##
        ### Define CSV file to write to
##
##
        #for row in rows:
        #    var_id = row.find('a').get_text(strip=True) if row.find('a') else 'N/A'
        #    cve_id = row.find_all('td')[1].get_text(strip=True) if row.find_all('td') else 'N/A'
        #    description = row.find_all('td')[2].get_text(strip=True) if row.find_all('td') else 'N/A'
        #    # Extract CVSS V2, CVSS V3, and Severity
        #    cvss_v2 = 'N/A'
        #    cvss_v3 = 'N/A'
        #    severity = 'N/A'
        #    cvss_severity_td = row.find_all('td')[3].get_text(strip=True) if len(row.find_all('td')) > 3 else ''
        #    if cvss_severity_td:
        #        cvss_v2_split = cvss_severity_td.split('CVSS V2: ')
        #        cvss_v2 = cvss_v2_split[1].split('\n')[0] if len(cvss_v2_split) > 1 else 'N/A'
        #        cvss_v3_split = cvss_severity_td.split('CVSS V3: ')
        #        cvss_v3 = cvss_v3_split[1].split('\n')[0] if len(cvss_v3_split) > 1 else 'N/A'
        #        severity_split = cvss_severity_td.split('Severity: ')
        #        severity = severity_split[1].split('<')[0] if len(severity_split) > 1 else 'N/A'
        #    # Write row data
        #    writer.writerow([var_id, cve_id, description, cvss_v2, cvss_v3, severity])

    # Output file path
    #print("Data has been written to vulnerabilities.csv")
    ##tools.l2f(cves, "../data/iot_data/iot_cvesV2.txt")
    #from bs4 import BeautifulSoup
    #import csv
    #
    ## Simulating loading HTML content. In practice, you would load the HTML content of each page.
#html_content = """Your HTML content here"""


