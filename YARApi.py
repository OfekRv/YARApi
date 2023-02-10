import os
import uuid
import yara
import pprint
import threading
import zipfile
import shutil
import discord
from discord import app_commands
from discord.ext import commands
from flask import Flask, request

app = Flask(__name__)
intents = discord.Intents.default()
chatbot_client = discord.Client(intents=intents)
bot = commands.Bot(intents=intents, command_prefix='/')
chatbot_command_tree = app_commands.CommandTree(chatbot_client)

PORT = os.environ.get('PORT', 5000)
BASE_FOLDER = os.environ.get('BASE_FOLDER', 'Uploads')
RULES_FOLDER = os.environ.get('RULES_FOLDER', 'YARA-rules')
YARA_INDEX_FILE = os.environ.get('YARA_INDEX_FILE', 'index.yar')
SAMPLE_FILE = os.environ.get('SAMPLE_FILE', 'sample.dnr')
YARA_MAX_STRING_PER_RULE = os.environ.get('YARA_MAX_STRING_PER_RULE', 5000000)
CHATBOT_TOKEN = os.getenv('CHATBOT_TOKEN', 'MTA3MzQ5MTczODExMjU2NTI3MA.GKQy-U.xQQB_XOiwqTIe3xiyPkLIemmfNdVFOrtvO1QD8')
CHATBOT_COMMAND_PREFIX = os.getenv('CHATBOT_COMMAND_PREFIX ', '/')
GUILD = os.getenv('CHATBOT_DISCORD_GUILD', '1073492750428807199')
SCAN_CHANNEL = os.getenv('SCAN_CHANNEL ', 1073526354924011580)

yara.set_config(max_strings_per_rule=YARA_MAX_STRING_PER_RULE)

scan_requests = {}
scan_results = {}

@chatbot_client.event
async def on_ready():
    await chatbot_command_tree.sync(guild=discord.Object(id=GUILD))
    
@chatbot_command_tree.command(name = "scan",
                              description = "Scan a file with your own rules set",
                              guild=discord.Object(id=GUILD)) 
async def scan_request(interaction, sample: discord.Attachment, rules_archive: discord.Attachment):
    if interaction.channel_id != SCAN_CHANNEL:
        await interaction.response.send_message("wrong channel, please switch to scanner channel :)")
        return    
    try:
        result = await generate_scan_request_result(sample, rules_archive)
    #TODO: create custom exception
    except Exception as e:
        await interaction.response.send_message(str(e))
    else:
        await interaction.response.send_message(format_chat_output(result))

@app.route('/scan', methods=['POST'])
def scan_request():
    sample = request.files['sample']
    rules_archive = request.files['rules']

    if sample.filename == '':
        return "Sample is missing", 400

    if rules_archive.filename == '':
        return "Rules are missing", 400
    if not zipfile.is_zipfile(rules_archive):
        return "rules set must be an archive!", 400

    request_uid = uuid.uuid1().hex
    rules_path = os.path.join(BASE_FOLDER, request_uid, RULES_FOLDER)    
    os.makedirs(rules_path)

    with zipfile.ZipFile(rules_archive, "r") as zip_ref:
        zip_ref.extractall(rules_path)
    
    sample_path = os.path.join(BASE_FOLDER, request_uid, SAMPLE_FILE)
    sample.save(sample_path)

    scan_requests.update({request_uid: {'status': 'Pending'}})
    threading.Thread(target=scan, args=(request_uid, sample_path, rules_path)).start()
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

async def generate_scan_request_result(sample, rules_archive):
    request_id, sample_path, rules_path = await submit_request(sample, rules_archive)
    result = scan(request_id, sample_path, rules_path)
    return result

async def generate_request_files(request_id, sample, rules_archive):
    if sample.filename == '':
        raise FileNotFoundError("Sample is missing!")
    if rules_archive.filename == '':
        raise FileNotFoundError("Rules are missing!")
    
    request_folder = os.path.join(BASE_FOLDER, request_id)
    rules_path = os.path.join(request_folder, RULES_FOLDER)    
    os.makedirs(rules_path)

    rules_archive_path = os.path.join(request_folder, rules_archive.filename)
    await rules_archive.save(rules_archive_path)
    sample_path = os.path.join(request_folder,SAMPLE_FILE)
    await sample.save(sample_path)
    
    if not zipfile.is_zipfile(rules_archive_path):
        raise TypeError("rules set must be an archive!")

    with zipfile.ZipFile(rules_archive_path, "r") as zip_ref:
        zip_ref.extractall(rules_path)

    return sample_path, rules_path

async def handle_scan_request(sample, rules_archive):
    request_id, sample_path, rules_path = submit_request(sample, rules_archive)
    threading.Thread(target=scan, args=(request_id, sample_path, rules_path)).start()
    return {'location': '/requests/' + request_id + '/status'}, 202

async def submit_request(sample, rules_archive):
    request_id = uuid.uuid1().hex
    sample_path, rules_path = await generate_request_files(request_id, sample, rules_archive)
    scan_requests.update({request_id: {'status': 'Pending'}})
    return request_id, sample_path, rules_path

def scan(request_id, sample_path, rules_path):
    index_file = search_file(rules_path, YARA_INDEX_FILE)
    rules = yara.compile(index_file, includes=True)
    matches = rules.match(sample_path)
    shutil.rmtree(os.path.join(BASE_FOLDER, request_id))
    rules_matched = []
    for match in matches:
        rules_matched.append({'rule': match.rule, 'meta': match.meta, 'strings': match.strings})    
    result = {'matches': rules_matched}
    submit_result(request_id, result)
    return result

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

def format_chat_output(output):
    return '`' + pprint.pformat(output, 2) + '`'

if __name__ == '__main__':
    chatbot_client.run(CHATBOT_TOKEN)
    app.run(threaded=True, port=PORT)