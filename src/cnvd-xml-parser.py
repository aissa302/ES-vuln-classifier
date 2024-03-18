import xml.etree.ElementTree as ET
import csv
import os
import re

def clean_text(text):
    """Clean the text by stripping leading/trailing whitespace and replacing sequences of whitespace with a single space."""
    return re.sub(r'\s+', ' ', text.strip())

def xml_to_csv(xml_file, csv_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Check if the root element has children
    if not list(root):
        print(f"No child elements found in {xml_file}. Skipping...")
        return

    # Open a CSV file for writing
    with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)

        # Assuming all children of the root have the same structure,
        # write the header row based on the first child
        header = [elem.tag for elem in root[0]]
        csvwriter.writerow(header)

        # Write the data rows, cleaning text nodes before writing
        for child in root:
            row = [clean_text(elem.text) if elem.text is not None else '' for elem in child]
            csvwriter.writerow(row)

def process_directory(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.xml'):
            xml_file = os.path.join(directory, filename)
            csv_file = os.path.join(directory, filename.replace('.xml', '.csv'))
            xml_to_csv(xml_file, csv_file)
            print(f"Converted {xml_file} to {csv_file}")

# Example usage - specify the path to your directory containing XML files
#process_directory('../data/CNVD/xml_files/')

#import xml.etree.ElementTree as ET
#import json
#import os
#from collections import defaultdict
#
#def xml_to_json(xml_file, json_file):
#    tree = ET.parse(xml_file)
#    root = tree.getroot()
#
#    def elem_to_dict(elem):
#        d = {elem.tag: {} if elem.attrib else None}
#        children = list(elem)
#        if children:
#            dd = defaultdict(list)
#            for dc in map(elem_to_dict, children):
#                for k, v in dc.items():
#                    dd[k].append(v)
#            d = {elem.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
#        if elem.text:
#            text = elem.text.strip()
#            if children or elem.attrib:
#                if text:
#                    d[elem.tag]['text'] = text
#            else:
#                d[elem.tag] = text
#        return d
#
#    with open(json_file, 'w', encoding='utf-8') as jsonf:
#        jsonf.write(json.dumps(elem_to_dict(root), indent=4, ensure_ascii=False))
#
#def process_directory(directory):
#    for filename in os.listdir(directory):
#        if filename.endswith('.xml'):
#            xml_file = os.path.join(directory, filename)
#            json_file = os.path.join(directory, filename.replace('.xml', '.json'))
#            xml_to_json(xml_file, json_file)
#            print(f"Converted {xml_file} to {json_file}")
#
## Example usage - specify the path to your directory containing XML files
#process_directory('../data/CNVD/xml_files/')
            
import os
import json
import pandas as pd
from tqdm import tqdm

def process_directory_to_excel(directory, excel_file):
    all_data_frames = []

    for filename in tqdm(os.listdir(directory)):
        if filename.endswith('.json'):
            json_file_path = os.path.join(directory, filename)
            
            try:
                # Load the JSON file
                with open(json_file_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
            except Exception as e:
                print(f"Error loading {json_file_path}: {e}")
                continue
            
            # Normalize the JSON data into a flat table
            if data['vulnerabilitys'] and data['vulnerabilitys']['vulnerability']:
                df = pd.json_normalize(data['vulnerabilitys']['vulnerability'])
            else:
                print(f"No data found in {json_file_path}. Skipping...")
                continue
            
            # Append the DataFrame to the list
            all_data_frames.append(df)

    # Concatenate all the data frames into one
    combined_df = pd.concat(all_data_frames, ignore_index=True)
    print(f"Combined {len(all_data_frames)} DataFrames into one.")
    combined_df.to_csv("../data/CNVD/cnvd_data.csv", index=False, encoding='utf-8-sig')
    # convert to excel
    #combined_df.to_excel(excel_file, index=False)

# Example usage
process_directory_to_excel('../data/CNVD/xml_files/', '../data/CNVD/output.xlsx')

