from concurrent.futures import thread
import os
import uuid
from wsgiref.util import request_uri
import yara
import time
import threading
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

PORT = os.environ.get('PORT', 5000)
YARA_EXTENSION = ".yar"

scan_requests = {}
scan_results = {}

@app.route('/scan', methods=['POST'])
def scan_request():
    #TODO: verify request
    request_uid = uuid.uuid1().hex
    scan_requests.update({request_uid: {'status': 'Pending'}})
    #asyncio.ensure_future(todo(request_uid))
    threading.Thread(target=todo, args=([request_uid])).start()
    return {'location': '/requests/' + request_uid + '/status'}, 202

@app.route('/requests/<request_id>/status', methods=['GET'])
def request_status(request_id):
    #TODO check if exist
    resource = scan_requests[request_id]
    status_code = 302 if resource['status'] == 'Completed' else 200
    return resource, status_code

@app.route('/results/<result_id>', methods=['GET'])
def scan_result(result_id):
    #TODO check if exist
    resource = scan_results[result_id];
    status_code = 200 if resource else 404
    return resource, status_code

def todo(request_id):
    time.sleep(5)
    scan_request = scan_requests[request_id]
    result_uid = uuid.uuid1().hex
    scan_results.update({result_uid: 'TODO'})
    scan_request['status'] = 'Completed'
    scan_request['result'] = '/results/' + result_uid
    scan_requests.update({request_id: scan_request})

def init_rules():
    logging.info('initing rules')
    
    # TODO: rules source from github url (?)
    rules = []

    for rule in rules:
        save_rule_file(rule['name'], rule['raw'])
    generate_index_rule()
    
    logging.info('rules initialized')

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

def save_rule_file(name, content):
    with open(name + YARA_EXTENSION, 'w') as rule_file:
        rule_file.write(content)

if __name__ == '__main__':
    app.run(threaded=True, port=PORT)