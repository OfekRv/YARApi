import os
import json
import time
import yara
import requests
import logging
from flask import Flask, request, jsonify
app = Flask(__name__)

PORT =  os.environ.get('PORT', 5000)
STORE_API_URL = os.environ.get('STORE_API_URL', 'http://localhost:9000')
STORE_API_USERNAME = os.environ.get('STORE_API_USERNAME', '**')
STORE_API_PASSWORD = os.environ.get('STORE_API_PASSWORD', '**')
STORE_API_YARA_ENGINE_NAME = os.environ.get('STORE_API_YARA_ENGINE_NAME', 'YARA')

YARA_EXTENSION = ".yar"

#TODO: fix path-traversal

@app.route('/scan', methods=['POST'])
def get_matches():
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

@app.route('/rules/<name>', methods=['GET'])
def get_rule(name):
    with open(name + '.yar', 'r') as rule_file:
        return rule_file.read()

@app.route('/rules/<name>', methods=['POST'])
def save_rule(name):
    rule = request.json['content']
    save_rule_file(name, rule)
    generate_index_rule()
    return name

@app.route('/rules/<name>', methods=['DELETE'])
def delete_rule(name):
    os.remove(name + YARA_EXTENSION)
    generate_index_rule()
    return name

def generate_index_rule():
    if os.path.exists('index'):
        os.remove('index')   
    
    with open('index', 'w') as rules:
        for rule_file in os.scandir(os.curdir):
            if rule_file.path.endswith(YARA_EXTENSION):
                rules.write('include \"' + rule_file.name + '\"\n')

    yara.compile(filepath='index', includes=True).save('compiled_index')

def init_rules():
    rules = requests.get(STORE_API_URL + "/api/rules?page=0&size=1000&eagerload=false",
                        auth=(STORE_API_USERNAME, STORE_API_PASSWORD)).json()
    for rule in rules:
        if rule['engine']['name'] == STORE_API_YARA_ENGINE_NAME: 
            save_rule_file(rule['name'], rule['raw'])
    generate_index_rule()

def save_rule_file(name, content):
    with open(name + YARA_EXTENSION, 'w') as rule_file:
        rule_file.write(content)

if __name__ == '__main__':
    try:
        init_rules()
    except:
        logging.warning('Could not init rules') 

    # TODO - no hardcoded port
    app.run(threaded=False, port=PORT)