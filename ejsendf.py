#!/usr/bin/env python

import hashlib
import hmac
import os
import random
import secrets
import string
import sys
import argparse
import hashlib
import requests

CONFIG_FILENAME = os.path.expanduser('~') + '/' + '.ejsendfc'
SECRET_LENGTH = 40

class Ejsendf():
    def __init__(self, user, password, secret, puturl):
        self.user=user
        self.password=password
        self.secret=secret
        self.puturl=puturl

    @staticmethod
    def upload_filename(sender, filename):
        sender_hash=hashlib.sha1(sender.encode('utf-8')).hexdigest()
        random_dir=''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(SECRET_LENGTH))
        basename=os.path.basename(filename)
        return sender_hash+'/'+random_dir+'/'+basename

    def calc_file_auth_token(self, filename, upload_filename):
        hmac_input = "{} {}".format(upload_filename, os.stat(filename).st_size)
        return hmac.new(self.secret.encode('utf-8'), hmac_input.encode('utf-8'), hashlib.sha256).hexdigest()

    def send(self, sender, recipient, filename):
        upload_filename=self.upload_filename(sender, filename)
        file_auth_token=self.calc_file_auth_token(filename, upload_filename)
        upload_url=self.puturl+'/'+upload_filename
        print(upload_url)
        with open(filename, 'rb') as f:
            r = requests.put(upload_url, data = f, params = {'v':file_auth_token})
        print(r)

if __name__ == '__main__':

    # parse opts
    parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
    parser.add_argument('-u', '--user', help='ejabberd\'s API-User', required=True)
    parser.add_argument('-p', '--password', help='Password', required=True)
    parser.add_argument('--secret', help='External secret from ejabberd\'s mod_http_upload', required=True)
    parser.add_argument('-s', '--sender', help='Sender', required=True)
    parser.add_argument('-r', '--recipient', help='Recipient', required=True)
    parser.add_argument('--puturl', help='ejabberd\'s put url', required=True)
    parser.add_argument('filename', help='File to upload')
    if os.path.isfile(CONFIG_FILENAME):
        args = parser.parse_args(['@'+CONFIG_FILENAME]+sys.argv[1:])
    else:
        args = parser.parse_args()

    # create sender object
    ejSender = Ejsendf(args.user, args.password, args.secret, args.puturl)

    # upload file and send from sender to recipient
    ejSender.send(args.sender, args.recipient, args.filename)
