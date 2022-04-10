import os
import json
import time
import yara
from flask import Flask, request, jsonify
app = Flask(__name__)

#TODO: fix path-traversal
#TODO: make thread safe (?)

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
    with open(name + '.yar', 'w') as rule_file:
        rule_file.write(rule)
    generate_index_rule()
    return name

@app.route('/rules/<name>', methods=['DELETE'])
def delete_rule(name):
    os.remove(name + '.yar')
    generate_index_rule()
    return name

def generate_index_rule():
    if os.path.exists('index'):
        os.remove('index')   
    
    with open('index', 'w') as rules:
        for rule_file in os.scandir(os.curdir):
            if rule_file.path.endswith('.yar'):
                rules.write('include \"' + rule_file.name + '\"\n')

    yara.compile(filepath='index', includes=True).save('compiled_index')

if __name__ == '__main__':
    # TODO - no hardcoded
    app.run(threaded=True, port=5000)