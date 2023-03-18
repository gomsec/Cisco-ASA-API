#!/usr/bin/python
# coding : utf-8

'''
Created on 12.10.2018
@author: MBU
'''



if __name__ == '__main__':
    pass

import requests
import urllib3
import json
import authentication
import acl
import importlib

importlib.reload(authentication)
importlib.reload(acl)

urllib3.disable_warnings()

IP = '34.226.223.215'
URL = 'https://' + IP

#Gets Token from ASA and stores it in an header.
token = authentication.Token
#token = authentication.Token1
Header = authentication.Header

#Get all standard IN ACLs from ASA
def get_acl_in(ip):
    data_json = None
    url = 'https://' + ip + '/api/access/in'
    r = requests.get(url, headers = authentication.Header, verify = False)
    if(not r):
        print("No Data returned")
    else:
        data_json = r.json()
    return data_json

#Get the object ID of an ACL
def get_acl_objectid(ip, aclname):
    data_json = None
    url = 'https://' + ip + '/api/objects/extendedacls/' + aclname + '/aces'
    r = requests.get(url, headers=authentication.Header, verify=False)
    if not r:
        print("No Data returned")
    else:
        data_json = r.json()
        #print("JSON Response: ", data_json)
        acl_objectId = data_json['items'][0]['objectId']
    return acl_objectId

#Get all extended ACLs from ASA
def get_all_ext_acl(ip):
    data_json = None
    url = 'https://' + ip + '/api/objects/extendedacls'
    #Make GET Request to ASA
    r = requests.get(url, headers = authentication.Header, verify = False)
    #If there is no response, write no data returned
    if(not r):
        print("No Data returned")
    else:
        data_json = r.json()
    return data_json

#Creates an extended ACL on ASA, needs an Token, IP-Address, a Name and the rule in JSON-Format
def add_ext_acl(ip, aclName, rule ):
    data_json = None
    #API-URL to add extended ACL Objects
    url = 'https://'+ip+'/api/objects/extendedacls/'+aclName+'/aces' 
    #Make a POST request to ASA API
    r = requests.request("POST", url, data=rule, headers=authentication.Header, verify=False)

#Deletes an extended ACL on ASA, needs an Token, IP-Address, a Name and acl object ID
def del_ext_acl(ip, aclName):
    data_json = None
    acl_objectId= get_acl_objectid(ip, aclName)
    #acl_objectId = acl_data['objectId']
    # API-URL to add extended ACL Objects
    url = 'https://' + ip + '/api/objects/extendedacls/' + aclName + '/aces/' + acl_objectId
    # Make a POST request to ASA API
    r = requests.delete(url, headers=authentication.Header, verify=False)






