#!/usr/bin/env python3
#
# export_scan_to_csv.py
#
# Export a Nessus scan to a CSV file.
# For API documentation, see https://127.0.0.1:8834/api#
#

import argparse
import json
import requests
import time
from operator import itemgetter
from urllib3.exceptions import InsecureRequestWarning

# set constants
HOST = '127.0.0.1'
PORT = 8834
BASE_URL = "https://{}:{}".format(HOST, PORT)

# define and parse arguments
parser = argparse.ArgumentParser(
    description='Export Nessus scan results to CSV', 
    epilog='Requires either API keys or username/password, and the requested action, either list all scans or a scan ID to export'
)
parser.add_argument('-a', '--accessKey', metavar='abc')
parser.add_argument('-s', '--secretKey', metavar='def')
parser.add_argument('-u', '--username', metavar='user')
parser.add_argument('-p', '--password', metavar='pass')
parser.add_argument('-l', '--list-scans', action='store_true', default=False, dest='list_scans')
parser.add_argument('-i', '--scan-id', type=int, dest='scan_id', metavar='ID')

args = parser.parse_args()

# function to check whether the given flags are compatible
def flags_are_compatible():
    # needs either (accessKey AND secretKey) OR (username AND password)
    # AND
    # (list_scans OR scan_id)

    if ( (args.accessKey is not None and args.secretKey is not None) or 
         (args.username  is not None and args.password  is not None) ):

        if args.list_scans or args.scan_id is not None:
            return True
        else:
            return False
    else: # no auth flags
        return False

if not flags_are_compatible():
    parser.print_help()
    exit()

# function to test authentication
# returns JSON scan list on success, False on failure
def able_to_authenticate(sess, header):
    url = "{}/scans".format(BASE_URL)
    response = sess.get(url, verify=False, headers=header)
    if response.status_code == 200:
        return json.loads(response.text)
    else:
        return False

# function to get new session token
# returns token on success, False on failure
def get_session_token(sess, user, pword):
    url = "{}/session".format(BASE_URL)
    payload = {'username': user, 'password': pword}
    response = sess.post(url, verify=False, data=payload)
    if response.status_code == 200:
        return json.loads(response.text)['token']
    else:
        return False

# build session and set requests settings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
session = requests.Session()

# test API keys or user/pass
if args.accessKey is not None: # API keys given
    auth_header = {'X-ApiKeys': "accessKey={}; secretKey={}".format(args.accessKey, args.secretKey)}
    scan_response_object = able_to_authenticate(session, auth_header)
    if scan_response_object == False:
        print('API key authentication failure')
        exit()
else: # no API keys, so username/password were given
    # get session token
    session_token = get_session_token(session, args.username, args.password)
    if session_token == False:
        print('Unable to get session token with username and password')
        exit()
    auth_header = {'X-Cookie': "token={}".format(session_token)}
    scan_response_object = able_to_authenticate(session, auth_header)
    if scan_response_object == False:
        print('Session token authentication failure')
        exit()

# if list scans, list and exit
if args.list_scans:
    url = "{}/scans".format(BASE_URL)
    scan_list = [ (scan['id'], scan['name']) for scan in scan_response_object['scans'] ]
    
    print('ID - Name')
    for scan in sorted(scan_list, key=itemgetter(0)):
        print("{} - {}".format(scan[0], scan[1]))
    exit()

# request export of specified scan
#   POST /scans/{scan_id}/export
#   format=csv
print('Requesting export...')
url = "{}/scans/{}/export".format(BASE_URL, args.scan_id)
payload = {'format': 'csv'}
response = session.post(url, verify=False, headers=auth_header, data=payload)
if response.status_code != 200:
    print('Unable to request scan export. Response:')
    print(response.text)
    exit()
response_object = json.loads(response.text)
file_id = response_object['file']

# loop while checking status of export
#   GET /scans/{scan_id}/export/{file_id}/status
print('Waiting until export is ready', end='', flush=True)
while True:
    url = "{}/scans/{}/export/{}/status".format(BASE_URL, args.scan_id, file_id)
    response = session.get(url, verify=False, headers=auth_header)
    if response.status_code != 200:
        # TODO: If using a session token, check its status and attempt renewing
        #   GET /tokens/{token}/status
        print()
        print('Unable to request export status. Response:')
        print(response.text)
        exit()
    response_object = json.loads(response.text)
    if response_object['status'] == 'ready':
        print()
        break
    else:
        print('.', end='', flush=True)
        time.sleep(2)

# attempt download
#  GET /scans/{scan_id}/export/{file_id}/download
print('Downloading file...')
url = "{}/scans/{}/export/{}/download".format(BASE_URL, args.scan_id, file_id)
response = session.get(url, verify=False, headers=auth_header)
if response.status_code != 200:
    print('Unable to download file. Response:')
    print(response.text)
    exit()

# open file to write CSV
scan_name = ''
for scan in scan_response_object['scans']:
    if scan['id'] == args.scan_id:
        scan_name = scan['name'].replace(' ', '_')
timestamp = time.strftime("%Y-%m-%d_%H%M%S")
file_name = "{}_{}.csv".format(scan_name, timestamp)
with open(file_name, 'w') as csv_file:
    csv_file.write(response.text)

print("CSV file written to '{}'".format(file_name))
