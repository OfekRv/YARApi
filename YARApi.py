import os
import uuid
import yara
import threading
from pathlib import Path
import zipfile
from flask import Flask, request

app = Flask(__name__)

PORT = os.environ.get('PORT', 5000)
BASE_FOLDER = "YARA-rules"
YARA_INDEX_FILE = "index.yar"

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
    rules_path = os.path.join(BASE_FOLDER, request_uid)    
    os.makedirs(rules_path)

    with zipfile.ZipFile(rules_archive, "r") as zip_ref:
        zip_ref.extractall(rules_path)
    scan_requests.update({request_uid: {'status': 'Pending'}})
    threading.Thread(target=scan, args=(request_uid, sample, rules_path)).start()
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

def scan(request_id, sample, rules_path):
    index_file = search_file(rules_path, YARA_INDEX_FILE)
    rules = yara.compile(index_file, includes=True)
    matches = rules.match(sample)
    os.rmdir(rules_path)
    submit_result(request_id, matches)

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
    app.run(threaded=True, port=PORT)