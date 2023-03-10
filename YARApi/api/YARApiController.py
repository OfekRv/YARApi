import os
import threading
import uuid
import zipfile

from errors.YARApiFileNotFoundError import YARApiFileNotFoundError
from flask import Flask, request
from scanners import YARAScanner

app = Flask(__name__)

HOST = os.environ.get('HOST', default='0.0.0.0')
PORT = os.environ.get('PORT', default=8080)
IS_DEBUG = os.environ.get('IS_DEBUG', default=False)
BASE_FOLDER = os.environ.get('BASE_FOLDER', default='Uploads')
RULES_FOLDER = os.environ.get('RULES_FOLDER', default='YARA-rules')
SAMPLE_FILE = os.environ.get('SAMPLE_FILE', default='sample.dnr')

scan_requests = {}
scan_results = {}

def run():
    app.run(host=HOST, port=PORT, threaded=True,debug=IS_DEBUG)

@app.route('/scan', methods=['POST'])
async def scan_request():
    sample = request.files['sample']
    rules_archive = request.files['rules']
    try:
        return await handle_scan_request(sample, rules_archive, save_file)
    except errors.YARApiError as e:
        return str(e), 400

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
    resource = scan_results[result_id]
    return resource, 200

async def generate_request_files(request_id, sample, rules_archive, save_method):
    if sample.filename == '':
        raise YARApiFileNotFoundError("Sample is missing!")
    if rules_archive.filename == '':
        raise YARApiFileNotFoundError("Rules are missing!")
    
    request_folder = os.path.join(BASE_FOLDER, request_id)
    rules_path = os.path.join(request_folder, RULES_FOLDER)    
    os.makedirs(rules_path)

    rules_archive_path = os.path.join(request_folder, rules_archive.filename)
    await save_method(rules_archive, rules_archive_path)
    sample_path = os.path.join(request_folder, SAMPLE_FILE)
    await save_method(sample, sample_path)
    
    if not zipfile.is_zipfile(rules_archive_path):
        raise YARApiRulesFileTypeError("rules set must be an archive!")

    with zipfile.ZipFile(rules_archive_path, "r") as zip_ref:
        zip_ref.extractall(rules_path)

    return sample_path, rules_path

async def handle_scan_request(sample, rules_archive, save_method):
    request_id, sample_path, rules_path = await submit_request(sample, rules_archive, save_method)
    #threading.Thread(target=scan, args=(request_id, sample_path, rules_path)).start()
    threading.Thread(target=YARAScanner.scan, args=(request_id, sample_path, rules_path)).start()
    return {'location': '/requests/' + request_id + '/status'}, 202

async def submit_request(sample, rules_archive, save_method):
    request_id = uuid.uuid1().hex
    sample_path, rules_path = await generate_request_files(request_id, sample, rules_archive, save_method)
    scan_requests.update({request_id: {'status': 'Pending'}})
    return request_id, sample_path, rules_path

def submit_result(request_id, result):
    scan_request = scan_requests[request_id]
    result_uid = uuid.uuid1().hex
    scan_results.update({result_uid: result})
    scan_request['status'] = 'Completed'
    scan_request['result'] = '/results/' + result_uid
    scan_requests.update({request_id: scan_request})

async def save_file(file, path):
    file.save(path)