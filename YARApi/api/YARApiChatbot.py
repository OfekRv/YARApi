import logging
import os
import pprint
from threading import Thread

import discord
from discord import app_commands
from discord.ext import commands
from errors.YARApiError import YARApiError
from managers import scan_manager
from scanners import YARAScanner

intents = discord.Intents.default()
chatbot_client = discord.Client(intents=intents)
bot = commands.Bot(intents=intents, command_prefix='/')
chatbot_command_tree = app_commands.CommandTree(chatbot_client)

CHATBOT_TOKEN = os.getenv('CHATBOT_TOKEN', default='')
CHATBOT_COMMAND_PREFIX = os.getenv('CHATBOT_COMMAND_PREFIX ', default='/')
GUILD = os.getenv('CHATBOT_DISCORD_GUILD', default='1073492750428807199')
SCAN_CHANNEL = int(os.getenv('SCAN_CHANNEL', default='1078635776058859613'))

def run():
    Thread(target=chatbot_client.run, args=([CHATBOT_TOKEN])).start()

@chatbot_client.event
async def on_ready():
    await chatbot_command_tree.sync(guild=discord.Object(id=GUILD))
    
@chatbot_command_tree.command(name = "scan_with_ruleset",
                              description = "Scan a file with your own rules set",
                              guild=discord.Object(id=GUILD)) 
async def scan_request(interaction, sample: discord.Attachment, rules_archive: discord.Attachment):
  await __handle_request(interaction, sample, None, rules_archive)

@chatbot_command_tree.command(name = "scan_with_single_rule",
                              description = "Scan a file with your own rule",
                              guild=discord.Object(id=GUILD)) 
async def scan_request(interaction, sample: discord.Attachment, rule: discord.Attachment):
    await __handle_request(interaction, sample, rule, None)

async def __handle_request(interaction, sample: discord.Attachment, rule: discord.Attachment, rules_archive: discord.Attachment):
    await interaction.response.defer()
    if interaction.channel_id != SCAN_CHANNEL:
        await interaction.followup.send("wrong channel, please switch to scanner channel :)")
    else:
        try:
            result = await scan_manager.generate_scan_request_result(sample, rules_archive, save_attachment)
        except YARApiError as e:
            await interaction.followup.send('ERROR: ' + str(e))
        except Exception as e:
            logging.exception(str(e))
            await interaction.followup.send('Unexpected error occured :(')
        else:
            await interaction.followup.send(__format_chat_output(result))


def __format_chat_output(output):
    return '`' + pprint.pformat(output, 2) + '`'

async def save_attachment(file, path):
    await file.save(path)