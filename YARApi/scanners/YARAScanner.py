import logging
import os
import pprint
import shutil

import yara
from errors.YARApiRulesFileSyntaxError import YARApiRulesFileSyntaxError
from yara import SyntaxError

BASE_FOLDER = os.environ.get('BASE_FOLDER', default='Uploads')

YARA_INDEX_FILE = os.environ.get('YARA_INDEX_FILE', default='index.yar')
YARA_MAX_STRING_PER_RULE = os.environ.get('YARA_MAX_STRING_PER_RULE', default=5000000)

yara.set_config(max_strings_per_rule=YARA_MAX_STRING_PER_RULE)

def scan(request_id, sample_path, rules_path):
    logging.info('start scanning request ' + request_id)
    index_file = search_file(rules_path, YARA_INDEX_FILE)
    logging.info('found index file of request ' + request_id)
    try:
        rules = yara.compile(index_file, includes=True)
    except SyntaxError as e:
        raise YARApiRulesFileSyntaxError(e) from None
    logging.info('rules request ' + request_id + 'compiled successfully')
    matches = rules.match(sample_path)
    logging.info('scan of request ' + request_id + 'finished')
    shutil.rmtree(os.path.join(BASE_FOLDER, request_id))
    logging.info('files request ' + request_id + 'deleted successfully')
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

def search_file(root, file_name):
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            if name == file_name:
                return os.path.join(dirpath, name)
    return None

def format_chat_output(output):
    return '`' + pprint.pformat(output, 2) + '`'

async def save_attachment(file, path):
    await file.save(path)
async def save_file(file, path):
    file.save(path)