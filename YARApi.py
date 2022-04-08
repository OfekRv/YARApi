import yara
from flask import Flask, request, jsonify
app = Flask(__name__)


@app.route('/rule', methods=['GET'])
def get_rule():
    return "rule"

@app.route('/rule', methods=['POST'])
def save_rule():
    return "new rule"

@app.route('/rule', methods=['DELETE'])
def delete_rule():
    return "no rule"


if __name__ == '__main__':
    # TODO - no hardcoded
    app.run(threaded=True, port=5000)