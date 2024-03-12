import xml.etree.ElementTree as ET
import csv
import os
import xmltodict
from tqdm import tqdm

# Function to parse XML files and write to CSV
def parse_xml_to_csv(xml_file, csv_file):
    print(f'Parsing {xml_file} to {csv_file}')

    tree = ET.parse(xml_file, parser=ET.XMLParser(encoding="utf-8"))
    root = tree.getroot()

    with open(csv_file, mode='w+', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Name', 'Vuln ID', 'Published', 'Modified', 'Severity', 'Vuln Type', 'Vuln Descript', 'CVE ID'])

        for entry in root.findall('entry'):
            name = entry.find('name').text
            vuln_id = entry.find('vuln-id').text
            published = entry.find('published').text
            modified = entry.find('modified').text
            severity = entry.find('severity').text
            vuln_type = entry.find('vuln-type').text
            vuln_descript = entry.find('vuln-descript').text
            cve_id = entry.find('other-id/cve-id').text

            writer.writerow([name, vuln_id, published, modified, severity, vuln_type, vuln_descript, cve_id])

# Path to the directory containing XML files
xml_directory = '../data/cnnvd-data/fixed_xml_files/'
csv_directory = '../data/cnnvd-data/cnnvd_csv_files/'

# Iterate over each XML file in the directory
for filename in tqdm(os.listdir(xml_directory)):
    if filename.endswith('.xml'):
        xml_file_path = os.path.join(xml_directory, filename)
        csv_file_path = os.path.join(csv_directory, os.path.splitext(filename)[0] + '.csv')
        parse_xml_to_csv(xml_file_path, csv_file_path)
#here you can change the encoding type to be able to set it to the one you need
#xmlstr = ET.tostring(xml_data, encoding='UTF-8', method='xml'
#data_dict = dict(xmltodict.parse(xmlstr))
