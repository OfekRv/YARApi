import os
import threading
import uuid
import zipfile

from errors.YARApiFileNotFoundError import YARApiFileNotFoundError
from errors.YARApiRulesFileTypeError import YARApiRulesFileTypeError
from scanners import YARAScanner
from utils.files_util import search_file

BASE_FOLDER = os.environ.get('BASE_FOLDER', default='Uploads')
RULES_FOLDER = os.environ.get('RULES_FOLDER', default='YARA-rules')
SAMPLE_FILE = os.environ.get('SAMPLE_FILE', default='sample.dnr')
YARA_INDEX_FILE = os.environ.get('YARA_INDEX_FILE', default='index.yar')

scan_requests = {}
scan_results = {}

async def submit_request(sample, rules_archive, single_rule_file, save_method):
    request_id = uuid.uuid1().hex
    sample_path, rule_path = await __generate_request_files(request_id,
                                                            sample,
                                                            rules_archive,
                                                            single_rule_file,
                                                            save_method)
    scan_requests.update({request_id: {'status': 'Pending'}})
    return request_id, sample_path, rule_path

async def generate_scan_request_result(sample, rules_archive, single_rule_file, save_method):
    request_id, sample_path, rule_path = await submit_request(sample, rules_archive, single_rule_file, save_method)
    return YARAScanner.scan(request_id, sample_path, rule_path)

async def handle_scan_request(sample, rules_archive, single_rule_file, save_method):
    request_id, sample_path, rule_path = await submit_request(sample, rules_archive, single_rule_file, save_method)
    threading.Thread(target=__execute_scan_and_submit_result, args=(request_id, sample_path, rule_path)).start()
    return {'location': '/requests/' + request_id + '/status'}, 202

def __execute_scan_and_submit_result(request_id, sample_path, rule_path):
    result = YARAScanner.scan(request_id, sample_path, rule_path)
    __submit_result(request_id, result)

def __submit_result(request_id, result):
    scan_request = scan_requests[request_id]
    result_uid = uuid.uuid1().hex
    scan_results.update({result_uid: result})
    scan_request['status'] = 'Completed'
    scan_request['result'] = '/results/' + result_uid
    scan_requests.update({request_id: scan_request})

async def __generate_request_files(request_id, sample, rules_archive, single_rule_file, save_method):
    if sample.filename == '':
        raise YARApiFileNotFoundError("Could not find sample")
    if (rules_archive is None or rules_archive.filename == '') and (single_rule_file is None or single_rule_file.filename == ''):
        raise YARApiFileNotFoundError("Could not find either rules archive nor single rule")
    
    request_folder = os.path.join(BASE_FOLDER, request_id)
    rules_path = os.path.join(request_folder, RULES_FOLDER)    
    os.makedirs(rules_path)

    sample_path = os.path.join(request_folder, SAMPLE_FILE)
    await save_method(sample, sample_path)

    if (rules_archive is not None and rules_archive.filename != ''):
        rule_path = await __generate_rules_files(rules_archive, save_method, request_folder, rules_path)
    else:
        rule_path = os.path.join(rules_path, YARA_INDEX_FILE)
        await save_method(single_rule_file, rule_path)

    return sample_path, rule_path

async def __generate_rules_files(rules_archive, save_method, request_folder, rules_path):
    rules_archive_path = os.path.join(request_folder, rules_archive.filename)
    await save_method(rules_archive, rules_archive_path)
    
    if not zipfile.is_zipfile(rules_archive_path):
        raise YARApiRulesFileTypeError("rules set must be an archive!")
    with zipfile.ZipFile(rules_archive_path, "r") as zip_ref:
        zip_ref.extractall(rules_path)

    index_rule = search_file(rules_path, YARA_INDEX_FILE)
    if index_rule == '':
        raise YARApiFileNotFoundError('Could not find index rule, must be named "' + YARA_INDEX_FILE + '"')
    return index_rule