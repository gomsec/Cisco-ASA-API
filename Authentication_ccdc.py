#!/usr/bin/python
# coding : utf-8
'''
Modified by gomsec
Derived from
Created on 12.10.2018
@author: MBU
https://github.com/MarcBuch/Cisco-ASA-API
'''


import requests
import urllib3
import json
import argparse
import datetime

urllib3.disable_warnings()

#reads IP, username, and password from a file
def read_credentials_from_file(file_path):
    with open(file_path, 'r') as f:
        ip = f.readline().strip()
        username = f.readline().strip()
        password = f.readline().strip()
    return ip, username, password

#gets token from ASA
def get_X_auth_token(ip, username, password):
    token = None
    url = 'https://' + username + ':' + password + '@' + ip + '/api/tokenservices'
    headers = {'Content-Type': "application/json"}
    payload = ""
    r = requests.request("POST", url, data=json.dumps(payload), headers=headers, verify=False)
    if not r:
        print("No Data returned")
    else:
        token = r.headers['x-auth-token']
        print("Token: " + token)
    return token

#deletes token from ASA
def del_X_auth_token(token, ip):
    url = 'https://'+ip+'/api/access/in'
    headers = Header
    r = requests.delete(url, headers=headers, verify=False)

#saves token information to a file
def save_token_info_to_file(token, ip, username, password):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_name = ip.replace(".","_")+"_token_info_" + timestamp.replace(" ", "_").replace(":", "-") + ".txt"

    with open(file_name, 'w') as f:
        f.write("Timestamp: " + timestamp + "\n")
        f.write("IP: " + ip + "\n")
        f.write("Username: " + username + "\n")
        f.write("Password: " + password + "\n")
        f.write("Token: " + token + "\n")

    print("Token information saved to file: " + file_name)

# Set up command-line argument parsing
parser = argparse.ArgumentParser(description="Cisco ASA API Authentication Script")
parser.add_argument("--ip", type=str, help="IP address of the Cisco ASA")
parser.add_argument("--username", type=str, help="Username for authentication")
parser.add_argument("--password", type=str, help="Password for authentication")
parser.add_argument("--file", type=str, help="Path to a file containing the IP, username, and password")

args = parser.parse_args()

if args.file:
    IP, username, password = read_credentials_from_file(args.file)
else:
    IP = args.ip
    username = args.username
    password = args.password

if not (IP and username and password):
    print("Error: Please provide the required arguments (IP, username, and password) or a file containing them.")
    parser.print_help()
    exit(1)

#Get Token from ASA
token = get_X_auth_token(IP, username, password)
Header = {
        'X-Auth-Token': token,
        'Content-Type':"application/json"   }
#save token information to a file
save_token_info_to_file(token, IP, username, password)

#Delete Token from ASA
#del_X_auth_token(token, IP)
