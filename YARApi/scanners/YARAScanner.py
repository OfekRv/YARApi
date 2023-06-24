import logging
import os
import shutil

import yara
from errors.YARApiRulesFileSyntaxError import YARApiRulesFileSyntaxError
from yara import SyntaxError

BASE_FOLDER = os.environ.get('BASE_FOLDER', default='Uploads')
YARA_MAX_STRING_PER_RULE = os.environ.get('YARA_MAX_STRING_PER_RULE', default=5000000)

yara.set_config(max_strings_per_rule=YARA_MAX_STRING_PER_RULE)

def scan(request_id, sample_path, rule):
    logging.info('start scanning request ' + request_id)
    try:
        rules = yara.compile(rule, includes=True)
    except SyntaxError as e:
        __delete_request_files(request_id)
        raise YARApiRulesFileSyntaxError(e) from None
    logging.info('rules request ' + request_id + 'compiled successfully')
    matches = rules.match(sample_path)
    logging.info('scan of request ' + request_id + 'finished')
    __delete_request_files(request_id)
    return __build_scan_response(matches) 

def __build_scan_response(matches):
    rules_matched = []
    for match in matches:
        matched_strings = []
        #TODO: data class for matched strings
        for matched_string in match.strings:
            matched_strings.append(str(matched_string))
        rules_matched.append({'rule': match.rule,
                              'meta': match.meta,
                              'strings': matched_strings})
    return {'matches': rules_matched}

def __delete_request_files(request_id):
    shutil.rmtree(os.path.join(BASE_FOLDER, request_id))
    logging.info('files request ' + request_id + 'deleted successfully')  