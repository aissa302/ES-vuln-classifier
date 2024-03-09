from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from tqdm import tqdm
from es_vuln_extraction import tools

tqdm.pandas()

# Headless browse
options = webdriver.ChromeOptions()
options.add_argument('--headless')

# Set up the Selenium WebDriver
driver = webdriver.Chrome("../driver/chromedriver", options=options)  # Replace with the appropriate driver for your browser
cves = []
for page_next in tqdm(range(1, 1991)):
    # Load the webpage
    driver.get(f"https://www.variotdbs.pl/vulns/?page={page_next}&amp;")

    # Click the link

    # Extract the updated HTML content
    html_content = driver.page_source

    # Assuming 'html_content' contains the HTML source code of the website
    soup = BeautifulSoup(html_content, 'html.parser')

    # Find all <td> elements that contain the CVE information
    cve_elements = soup.find_all('td')

    # Extract the CVE information from the elements
    for cve_element in cve_elements:
        cve = cve_element.get_text().strip()
        if cve.startswith('CVE-'):
            cves.append(cve)
tools.l2f(cves, "../data/iot_data/iot_cves.txt")
