import os
import yara
from flask import Flask, request, jsonify
app = Flask(__name__)

#TODO: fix path-traversal
#TODO: make thread safe (?)

@app.route('/rule/<name>', methods=['GET'])
def get_rule(name):
    with open(name + '.yar', 'r') as rule_file:
        return rule_file.read()

@app.route('/rule/<name>', methods=['POST'])
def save_rule(name):
    rule = request.json['content']

    with open(name + '.yar', 'w') as rule_file:
        rule_file.write(rule)
    return name

@app.route('/rule/<name>', methods=['DELETE'])
def delete_rule(name):
    os.remove(name + '.yar')
    return name

if __name__ == '__main__':
    # TODO - no hardcoded
    app.run(threaded=True, port=5000)