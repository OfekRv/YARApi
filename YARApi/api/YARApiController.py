import os

from errors.YARApiError import YARApiError
from flask import Flask, request
from managers import scan_manager

app = Flask(__name__)

HOST = os.environ.get('HOST', default='0.0.0.0')
PORT = os.environ.get('PORT', default=8080)
IS_DEBUG = os.environ.get('IS_DEBUG', default=False)
BASE_FOLDER = os.environ.get('BASE_FOLDER', default='Uploads')
RULES_FOLDER = os.environ.get('RULES_FOLDER', default='YARA-rules')
SAMPLE_FILE = os.environ.get('SAMPLE_FILE', default='sample.dnr')

def run():
    app.run(host=HOST, port=PORT, threaded=True,debug=IS_DEBUG)

@app.route('/scan', methods=['POST'])
async def scan_request():
    sample = request.files['sample']
    rules_archive = request.files['rules'] if "rules" in request.files else None
    single_rule_file = request.files['rule'] if "rule" in request.files else None
    try:
        return await scan_manager.handle_scan_request(sample, rules_archive, single_rule_file, save_file)
    except YARApiError as e:
        return str(e), 400

@app.route('/requests/<request_id>/status', methods=['GET'])
def request_status(request_id):
    if request_id not in scan_manager.scan_requests:
        return "Request not found", 404
    resource = scan_manager.scan_requests[request_id]
    status_code = 302 if resource['status'] == 'Completed' else 200
    return resource, status_code

@app.route('/results/<result_id>', methods=['GET'])
def scan_result(result_id):
    if result_id not in scan_manager.scan_results:
        return "Result not found", 404
    resource = scan_manager.scan_results[result_id]
    return resource, 200

async def save_file(file, path):
    file.save(path)