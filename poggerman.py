import discord
from discord.ext import commands
import binascii
import hashlib
import os
import re
import base65536
import json
import urllib.request

TOKEN = ''

client = commands.Bot(command_prefix = './')

error_idk = "```I don't know```"
error_too_long = "```Too Long!```"

def yes_encoding(arguement):
    return arguement.encode()

def no_encoding(arguement):
    return arguement

@client.event
async def on_ready():
    print("Status: Ready!")

@client.command()
async def goals(ctx):
    file = open("goals.txt","r")
    goals = "```" + file.read() + "```"
    file.close()
    await ctx.send(goals)

@client.command()
async def strhex(ctx, *, content: yes_encoding):
    """<string> : encodes string to hexadecimal"""
    if len(content) < 1500:
        await ctx.send("```" + binascii.hexlify(content).decode('utf-8') + "```")
    if len(content) > 1500:
        await ctx.send(error_too_long)

@client.command()
async def hexstr(ctx, *, content: yes_encoding):
    """<hexadecimal> : decodes hexadecimal to string"""
    if len(content) < 1500:
        await ctx.send("```" + binascii.unhexlify(content).decode('utf-8') + "```")
    if len(content) > 1500:
        await ctx.send(error_too_long)

@client.command()
async def md5(ctx, *, content: no_encoding):
    """<string> : hashes string to md5 hash"""
    if len(content) > 1500:
        await ctx.send(error_too_long)
    if len(content) < 1500:
        content = hashlib.md5(content.encode())
        await ctx.send("```" + content.hexdigest() + "```")

@client.command()
async def sha1(ctx, *, content: no_encoding):
    """<string> : hashes string to sha1 hash"""
    if len(content) > 1500:
        await ctx.send(error_too_long)
    if len(content) < 1500:
        content = hashlib.sha1(content.encode())
        await ctx.send("```" + content.hexdigest() + "```")

@client.command()
async def sha224(ctx, *, content: no_encoding):
    """<string> : hashes string to sha224 hash"""
    if len(content) > 1500:
        await ctx.send(error_too_long)
    if len(content) < 1500:
        content = hashlib.sha224(content.encode())
        await ctx.send("```" + content.hexdigest() + "```")

@client.command()
async def sha256(ctx, *, content: no_encoding):
    """<string> : hashes string to sha256"""
    if len(content) > 1500:
        await ctx.send(error_too_long)
    if len(content) < 1500:
        content = hashlib.sha256(content.encode())
        await ctx.send("```" + content.hexdigest() + "```")

@client.command()
async def sha384(ctx, *, content: no_encoding):
    """<string> : hashes string to sha384"""
    if len(content) > 1500:
        await ctx.send(error_too_long)
    if len(content) < 1500:
        content = hashlib.sha384(content.encode())
        await ctx.send("```" + content.hexdigest() + "```")

@client.command()
async def sha512(ctx, *, content: no_encoding):
    """<string> : hashes string to sha512"""
    if len(content) > 1500:
        await ctx.send(error_too_long)
    if len(content) < 1500:
        content = hashlib.sha512(content.encode())
        await ctx.send("```" + content.hexdigest() + "```")

@client.command()
async def guess_hash(ctx, *, content: no_encoding):
    """<hash> : guesses the hash function according to length"""
    content = len(content)
    hash_function_lengths = [32 , 40 , 56 , 64 , 96 , 128]

    if content == 32:
        await ctx.send("```MD5```")
    if content == 40:
        await ctx.send("```SHA-1```")
    if content == 56:
        await ctx.send("```SHA-224```")
    if content == 64:
        await ctx.send("```SHA-256```")
    if content == 96:
        await ctx.send("```SHA-384```")
    if content == 128:
        await ctx.send("```SHA512```")
    if content not in hash_function_lengths:
        await ctx.send(error_idk)
    if content > 1500:
        await ctx.send(error_too_long)

"""
@client.command(hidden = True)
async def nmap(ctx, *, content: no_encoding):
    <IPv4> : full nmap scan
    if re.search("^192", content) == False:
        result = os.popen("nmap -p 22 -Pn " + content).read()
        await ctx.send("```" + result + "```")
    if re.search("^192", content) == True:
        await ctx.send("```No```")
"""
# use the nmap3 module

@client.command()
async def ebase65536(ctx, *, content: no_encoding):
    """<string> : encodes string to base65536"""
    content = base65536.encode(content)
    await ctx.send(content)

@client.command()
async def sourcecode(ctx):
    file = open("poggerman.py","r")
    sourcecode = "```" + file.read() + "```"
    file.close()
    await ctx.send(sourcecode)

@client.command()
async def C19(ctx):
    data = urllib.request.urlopen("https://api.covid19api.com/summary").read()
    info = json.loads(data)
    await ctx.send("```" + "Total Deaths in the United States: " + str(info["Countries"][181]["TotalDeaths"]) + "```")

client.run(TOKEN)
