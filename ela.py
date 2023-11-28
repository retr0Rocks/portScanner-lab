import requests, json, os
from elasticsearch import Elasticsearch
import hashlib

"""
Core utility of this script is to pass all parsed json logs files to ElasticSeach api.
IMPORTANT: this script expects all the logs to be the logs file which should be in the same directory as this scipt.
"""
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()

es = Elasticsearch(["http://13.37.141.247:9200"], http_auth=('elastic', 'changeme'))

json_directory = os.getcwd() + '/logs/'
i = 0

for filename in os.listdir(json_directory):
    if filename.endswith(".json"):
        ff = filename
        filename = os.getcwd() + "/logs/" + filename
        file_hash = str(calculate_sha256(filename).hex())
        f = open(filename)
        docket_content = str(f.read())
        idx = 'logs-' + str(ff.replace(".json", "")) + file_hash
        es.index(index=idx, ignore=400, id=i, body=json.loads(json.dumps(docket_content)))
        i = i + 1
        print("inserted : ", idx)        
