from asyncio.windows_events import NULL
import os
import json
import time
import yara
import requests
import logging
from flask import Flask, request, jsonify
app = Flask(__name__)

PORT =  os.environ.get('PORT', 5000)
STORE_API_YARA_ENGINE_NAME = os.environ.get('STORE_API_YARA_ENGINE_NAME', 'YARA')
STORE_API_RETRY_INTERVAL = os.environ.get('STORE_API_RETRY_INTERVAL', 60)

YARA_EXTENSION = ".yar"

#TODO: fix path-traversal

#TODO: deprected
@app.route('/scan', methods=['POST'])
def scan():
    if not os.path.exists('compiled_index'):
        init_rules()

    rules = yara.load('compiled_index')
    text = request.json['content']

    sample_file_name = str(time.time_ns())
    with open(sample_file_name, 'w') as sample:
        sample.write(text)
    
    matches = rules.match(sample_file_name)
    os.remove(sample_file_name)
    print(matches)
    rules_matched = []
    for match in matches:
        rules_matched.append(match.rule)
    return {'matches': rules_matched}

@app.route('/scan', methods=['POST'])
def scan_request():
    #TODO: verify request first

    #TODO: should return: 202, request id
    return {'result': '/result/request_id/status'}

# consider the URI
@app.route('/result/<request_id>/status', methods=['GET'])
def request_status():
    # TODO: if no resposne - 200, else - 302 + resource redirect (?)
    if request:
        # TODO: status code 302
        return {'result': '/result/request_id','status': 'Completed'}
    
    # TODO: status code 200
    return {'status': 'Pending'}

# consider the URI
@app.route('/result/<request_id>', methods=['GET'])
def request_result():
    # TODO: if no resposne - 200, else - 302 + resource redirect (?)
    return {'matches': 'STUB'}

@app.route('/rules/<name>', methods=['POST'])
def save_rule(name):
    rule = request.json['content']
    save_rule_file(name, rule)
    generate_index_rule()
    return name

def generate_index_rule():
    logging.info('generating index rule')
    if os.path.exists('index'):
        os.remove('index')   
    
    with open('index', 'w') as rules:
        for rule_file in os.scandir(os.curdir):
            if rule_file.path.endswith(YARA_EXTENSION):
                rules.write('include \"' + rule_file.name + '\"\n')

    yara.compile(filepath='index', includes=True).save('compiled_index')
    logging.info('index rule compiled')

def init_rules():
    logging.info('initing rules')
    # TODO: rules source from github url (?)
    rules = []
    #rules = requests.get(STORE_API_URL + "/api/rules?page=0&size=1000&eagerload=false",
    #                    auth=(STORE_API_USERNAME, STORE_API_PASSWORD)).json()
    for rule in rules:
        save_rule_file(rule['name'], rule['raw'])
    generate_index_rule()
    logging.info('rules initialized')

def save_rule_file(name, content):
    with open(name + YARA_EXTENSION, 'w') as rule_file:
        rule_file.write(content)

if __name__ == '__main__':
    app.run(threaded=False, port=PORT)