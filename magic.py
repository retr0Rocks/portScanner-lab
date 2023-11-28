import argparse
import os
import json
from datetime import *
from be_scan import *
import hashlib

"""
Core utility of this python script is parsing output and preparing it to pass it to Elastcisearch as a valid format.
First, it checks either there is a previous logs file exists in, the logs/ directory, if the latter is true we flag it as an update to the previous logs. (1)
if not, this mean it's the first scan. (2)
Case 1 :
    - We itterate over the logs file and diff it with the new logs file.
    - update specific fields if condition is met.
Case 2:
    - Create new logs file.
    - Save all new logs into it.
"""


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()

def parse_output_file(input_file):
    with open(input_file, 'r') as f:
        data = json.loads(f.read())
    return data

def find_open_ports(data, max_port):
    open_ports = []
    for entry in data:
        filename = "logs/" + entry["user_hostname"] + ".json"
        #binary_edge_info = scan(entry["user_hostname"])
        #formatted_be_info = json.loads(binary_edge_info)
        if os.path.exists(filename):
            # If file exists, load the existing data and update it with new data
            with open(filename, 'r') as f:
                host_result = json.load(f)
            host_result['vulns'] = entry.get('vulns', None)
            host_result['fingerprint'] = str(calculate_sha256(filename).hex())
            for port_info in entry['ports']:
                port_found = False
                for existing_port in host_result['ports']:
                    if existing_port['port'] == port_info['port']:
                        existing_port.update({
                            'status': 'open',
                            'service': port_info['service'],
                            'protocol': port_info['protocol'],
                            'last_scan': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'last_seen_open' :datetime.now().strftime("%Y-%M-%d %H %M %S")
                        })
                        port_found = True
                        break
                if not port_found:
                    new_open_port = {
                        'port': port_info['port'],
                        'status': 'open',
                        'service': port_info['service'],
                        'protocol': port_info['protocol'],
                        'last_scan': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'last_seen_open' : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'last_seen_close' : None
                    }
                    host_result['ports'].append(new_open_port)
            
            # Update the last scan time for the host
            host_result['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Create new host_result data
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            host_result = {
                'ip': entry['ip'],
                'hostnames': entry['hostnames'],
                'user_hostname': entry['user_hostname'],
                'last_scan': date,
                'vulns' : entry.get('vulns', None),
                'ports': []
            }
            
            for port in range(1, max_port + 1):
                port_found = False
                for port_info in entry['ports']:
                    if port_info['port'] == port:
                        open_port = {
                            'port': port,
                            'status': 'open',
                            'service': port_info['service'],
                            'protocol': port_info['protocol'],
                            'last_scan': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'last_seen_open' : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'last_seen_close' : None
                        }
                        host_result['ports'].append(open_port)
                        port_found = True
                        break
                if not port_found:
                    closed_port = {
                        'port': port,
                        'status': 'closed',
                        'service': None,
                        'protocol': None,
                        'last_scan': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'last_seen_open' : None,
                        'last_seen_close' : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    host_result['ports'].append(closed_port)
        
        open_ports.append(host_result)
    
    return open_ports

def save_results_to_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Process output data and find open/closed ports.')
    parser.add_argument('input_file', type=str, help='Path to the input JSON file')
    parser.add_argument('max_port', type=int, help='Maximum port number to check')
    args = parser.parse_args()

    input_file = args.input_file
    max_port = args.max_port

    data = parse_output_file(input_file)
    open_ports = find_open_ports(data, max_port)

    for host_result in open_ports:
        host = host_result['user_hostname']
        output_filename = f'logs/{host}.json'
        save_results_to_file(output_filename, host_result)

if __name__ == '__main__':
    main()
