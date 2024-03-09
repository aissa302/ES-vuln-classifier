import json
import pandas as pd


def load_json_data(file):
    try:
        with open(file, 'r') as f:
            data = json.load(f)
        return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {file}: {e}")
        return None

# Using a function to load CSV files can also be helpful
def load_csv_data(file):
    try:
        return pd.read_csv(file)
    except Exception as e:
        print(f"Error loading {file}: {e}")
        return None

def get_num_cves(data):
    num_cves = 0
    if data:
        for keyword in data:
            num_cves += len(data[keyword]['cves']['id'])
    return num_cves

def save_json_data(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def find_intersection_and_clean_data(file_path1, file_path2, path):
    # Load data from both files
    data1 = load_json_data(file_path1)
    data2 = load_json_data(file_path2)

    # Extract the CVE IDs
    cves1 = set(data1[list(data1.keys())[0]]['cves']['id'])
    cves2 = set(data2[list(data2.keys())[0]]['cves']['id'])

    # Find the intersection of CVEs
    intersection = cves1.intersection(cves2)

    # Save intersection to a separate file
    intersection_data = {'common_cves': list(intersection)}
    save_json_data(intersection_data, f'{path}/common_cves.json')

    # Remove the intersecting CVEs from both datasets
    data1[list(data1.keys())[0]]['cves']['id'] = list(cves1 - intersection)
    data2[list(data2.keys())[0]]['cves']['id'] = list(cves2 - intersection)

    return data1, data2
