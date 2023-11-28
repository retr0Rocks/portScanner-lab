from pybinaryedge import BinaryEdge
import socket
import argparse
import json

"""
This script uses the binary edge api and return grabbed data.
"""
api_key = '5935b2f4-0638-4da0-b72f-edb1ec5ca032'
be = BinaryEdge(api_key)

def host_to_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        print(f"Error: {e}")

def scan(hostname):
    ip = host_to_ip(hostname)
    response = be.host(ip)

    formatted_response = json.dumps(response, indent=4)

    events = response.get('events', [])
    formatted_events = json.dumps(events, indent=4)
    ports_and_services = set()  # Using a set to store unique (port, service) pairs
    for event in events:
        port = event.get('port')

        # Access the 'results' list
        results = event.get('results', [])
        for result in results:
            target = result.get("target", {})
            protocol = target.get("protocol")
            res = result.get("result", {})
            data = res.get('data', {})
            service = data.get('service', {})
            service_name = service.get('name', None)
            if port and service_name:
                ports_and_services.add((ip, port, protocol, service_name))  # Convert to tuple here

    formatted_ports_and_services = list(ports_and_services)
    formatted_json_data = []
    for entry in formatted_ports_and_services:
        ip = entry[0]
        port = entry[1]
        protocol = entry[2]
        service = entry[3]
        formatted_json_data.append({'ip': ip, 'port': port, 'protocol': protocol, 'service': service})

    return json.dumps(formatted_json_data, indent=4)
"""
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Binary Edge scan")
    parser.add_argument("host", help="Hostname")
    args = parser.parse_args()
    hostname = args.host
    ip = host_to_ip(hostname)
    scan(ip)
"""
