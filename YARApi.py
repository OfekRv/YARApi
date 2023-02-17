import os
import uuid
import yara
import threading
import zipfile
import shutil
import logging
from flask import Flask, request

app = Flask(__name__)

PORT = os.environ.get('PORT', 5000)
IS_DEBUG = os.environ.get('IS_DEBUG', False)
BASE_FOLDER = os.environ.get('BASE_FOLDER', 'Uploads')
RULES_FOLDER = os.environ.get('RULES_FOLDER', 'YARA-rules')
YARA_INDEX_FILE = os.environ.get('YARA_INDEX_FILE', 'index.yar')
SAMPLE_FILE = os.environ.get('SAMPLE_FILE', 'sample.dnr')
YARA_MAX_STRING_PER_RULE = os.environ.get('YARA_MAX_STRING_PER_RULE', 5000)

yara.set_config(max_strings_per_rule=YARA_MAX_STRING_PER_RULE)

scan_requests = {}
scan_results = {}

@app.route('/scan', methods=['POST'])
def scan_request():
    sample = request.files['sample']
    rules_archive = request.files['rules']

    if sample.filename == '':
        return "Sample is missing", 400

    if rules_archive.filename == '':
        return "Rules are missing", 400
    if not zipfile.is_zipfile(rules_archive):
        return "You must archive the rules set", 400

    request_uid = uuid.uuid1().hex
    rules_path = os.path.join(BASE_FOLDER, request_uid, RULES_FOLDER)    
    os.makedirs(rules_path)

    with zipfile.ZipFile(rules_archive, "r") as zip_ref:
        zip_ref.extractall(rules_path)
    
    sample_path = os.path.join(BASE_FOLDER, request_uid, SAMPLE_FILE)
    sample.save(sample_path)

    scan_requests.update({request_uid: {'status': 'Pending'}})
    threading.Thread(target=scan, args=(request_uid, sample_path, rules_path)).start()
    return {'location': '/requests/' + request_uid + '/status'}, 202

@app.route('/requests/<request_id>/status', methods=['GET'])
def request_status(request_id):
    if request_id not in scan_requests:
        return "Request not found", 404
    resource = scan_requests[request_id]
    status_code = 302 if resource['status'] == 'Completed' else 200
    return resource, status_code

@app.route('/results/<result_id>', methods=['GET'])
def scan_result(result_id):
    if result_id not in scan_results:
        return "Result not found", 404
    resource = scan_results[result_id];
    return resource, 200

def scan(request_id, sample_path, rules_path):
    logging.info('start scanning request ' + request_id)
    index_file = search_file(rules_path, YARA_INDEX_FILE)
    logging.info('found index file of request ' + request_id)
    rules = yara.compile(index_file, includes=True)
    logging.info('rules request ' + request_id + 'compiled successfully')
    matches = rules.match(sample_path)
    logging.info('scan of request ' + request_id + 'finished')
    shutil.rmtree(os.path.join(BASE_FOLDER, request_id))
    logging.info('files request ' + request_id + 'deleted successfully')
    rules_matched = []
    for match in matches:
        rules_matched.append(match.rule)    
    submit_result(request_id, { 'matches': rules_matched })
    logging.info('submmited result of request: ' + request_id)

def submit_result(request_id, result):
    scan_request = scan_requests[request_id]
    result_uid = uuid.uuid1().hex
    scan_results.update({result_uid: result})
    scan_request['status'] = 'Completed'
    scan_request['result'] = '/results/' + result_uid
    scan_requests.update({request_id: scan_request})

def search_file(root, file_name):
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            if name == file_name:
                return os.path.join(dirpath, name)
    return None

if __name__ == '__main__':
    app.run(threaded=True,debug=IS_DEBUG, port=PORT)