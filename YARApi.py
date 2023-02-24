import logging
import os
import pprint
import shutil
import threading
from threading import Thread
import uuid
import zipfile

import discord
import yara
from discord import app_commands
from discord.ext import commands
from flask import Flask, request

from YARApiError import (YARApiError, YARApiFileNotFoundError,
                         YARApiRulesFileTypeError)

app = Flask(__name__)
intents = discord.Intents.default()
chatbot_client = discord.Client(intents=intents)
bot = commands.Bot(intents=intents, command_prefix='/')
chatbot_command_tree = app_commands.CommandTree(chatbot_client)

HOST = os.environ.get('HOST', default='0.0.0.0')
PORT = os.environ.get('PORT', default=8080)
IS_DEBUG = os.environ.get('IS_DEBUG', default=False)
BASE_FOLDER = os.environ.get('BASE_FOLDER', default='Uploads')
RULES_FOLDER = os.environ.get('RULES_FOLDER', default='YARA-rules')
YARA_INDEX_FILE = os.environ.get('YARA_INDEX_FILE', default='index.yar')
SAMPLE_FILE = os.environ.get('SAMPLE_FILE', default='sample.dnr')
YARA_MAX_STRING_PER_RULE = os.environ.get('YARA_MAX_STRING_PER_RULE', default=5000000)
CHATBOT_TOKEN = os.getenv('CHATBOT_TOKEN', default='')
CHATBOT_COMMAND_PREFIX = os.getenv('CHATBOT_COMMAND_PREFIX ', default='/')
GUILD = os.getenv('CHATBOT_DISCORD_GUILD', default='0')
SCAN_CHANNEL = int(os.getenv('SCAN_CHANNEL', default='0'))

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
    await interaction.response.defer()
    if interaction.channel_id != SCAN_CHANNEL:
        await interaction.response.send_message("wrong channel, please switch to scanner channel :)")
        return    
    try:
        result = await generate_scan_request_result(sample, rules_archive, save_attachment)
    except YARApiError as e:
        await interaction.followup.send(str(e))
    except:
        await interaction.followup.send('Unexpected error occured :(')
    else:
        await interaction.followup.send(format_chat_output(result))

@app.route('/scan', methods=['POST'])
async def scan_request():
    sample = request.files['sample']
    rules_archive = request.files['rules']
    try:
        return await handle_scan_request(sample, rules_archive, save_file)
    except YARApiError as e:
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
    resource = scan_results[result_id];
    return resource, 200

async def generate_scan_request_result(sample, rules_archive, save_method):
    request_id, sample_path, rules_path = await submit_request(sample, rules_archive, save_method)
    result = scan(request_id, sample_path, rules_path)
    return result

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
    sample_path = os.path.join(request_folder,SAMPLE_FILE)
    await save_method(sample, sample_path)
    
    if not zipfile.is_zipfile(rules_archive_path):
        raise YARApiRulesFileTypeError("rules set must be an archive!")

    with zipfile.ZipFile(rules_archive_path, "r") as zip_ref:
        zip_ref.extractall(rules_path)

    return sample_path, rules_path

async def handle_scan_request(sample, rules_archive, save_method):
    request_id, sample_path, rules_path = await submit_request(sample, rules_archive, save_method)
    threading.Thread(target=scan, args=(request_id, sample_path, rules_path)).start()
    return {'location': '/requests/' + request_id + '/status'}, 202

async def submit_request(sample, rules_archive, save_method):
    request_id = uuid.uuid1().hex
    sample_path, rules_path = await generate_request_files(request_id, sample, rules_archive, save_method)
    scan_requests.update({request_id: {'status': 'Pending'}})
    return request_id, sample_path, rules_path

def scan(request_id, sample_path, rules_path):
    logging.info('start scanning request ' + request_id)
    index_file = search_file(rules_path, YARA_INDEX_FILE)
    logging.info('found index file of request ' + request_id)
    rules = yara.compile(index_file, includes=True)
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
    result = {'matches': rules_matched}
    submit_result(request_id, result)
    logging.info('submmited result of request: ' + request_id)
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

async def save_attachment(file, path):
    await file.save(path)
async def save_file(file, path):
    file.save(path)

if __name__ == '__main__':
    Thread(target=chatbot_client.run, args=([CHATBOT_TOKEN])).start()
    app.run(host=HOST, port=PORT, threaded=True,debug=IS_DEBUG)
