#!/usr/bin/env python

import argparse
import hashlib
import hmac
import lxml.etree
import os
import random
import requests
import secrets
import string
import sys


CONFIG_FILENAME=os.path.expanduser('~')+'/'+'.ejsendfc'
SECRET_LENGTH=40

class Ejsendf():
    def __init__(self, user, password, secret, puturl, apiurl):
        self.user=user
        self.password=password
        self.secret=secret
        self.puturl=puturl
        self.apiurl=apiurl

    @staticmethod
    def upload_filename(sender, filename):
        sender_hash=hashlib.sha1(sender.encode('utf-8')).hexdigest()
        random_dir=''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(SECRET_LENGTH))
        basename=os.path.basename(filename)
        return sender_hash+'/'+random_dir+'/'+basename

    @staticmethod
    def oob_stanza(geturl):
        message=lxml.etree.Element('message', type='chat')
        body=lxml.etree.SubElement(message, 'body')
        body.text=geturl
        x=lxml.etree.SubElement(message, 'x', xmlns='jabber:x:oob')
        url=lxml.etree.SubElement(x, 'url')
        url.text=geturl
        return lxml.etree.tostring(message).decode('utf-8')

    def calc_file_auth_token(self, filename, upload_filename):
        hmac_input="{} {}".format(upload_filename, os.stat(filename).st_size)
        return hmac.new(self.secret.encode('utf-8'), hmac_input.encode('utf-8'), hashlib.sha256).hexdigest()

    def upload(self, sender, filename):
        upload_filename=self.upload_filename(sender, filename)
        file_auth_token=self.calc_file_auth_token(filename, upload_filename)
        upload_url=self.puturl+'/'+upload_filename
        with open(filename, 'rb') as f:
            try:
                r=requests.put(upload_url, data=f, params={'v': file_auth_token})
                r.raise_for_status()
            except requests.exceptions.RequestException:
                print("Error uploading file. Request response: ", r.content)
                raise
            return upload_url

    def send(self, sender, recipient, geturl):
        data={
            'from': sender,
            'to': recipient,
            'stanza': self.oob_stanza(geturl)
        }
        try:
            r=requests.post(self.apiurl+'/send_stanza', json=data, auth=(self.user, self.password))
            r.raise_for_status()
        except requests.exceptions.RequestException:
            print("Error sending message. Request response: ", r.content)
            raise

if __name__=='__main__':

    # parse opts
    parser=argparse.ArgumentParser(fromfile_prefix_chars='@')
    parser.add_argument('-u', '--user', help='ejabberd\'s API-User', required=True)
    parser.add_argument('-p', '--password', help='Password', required=True)
    parser.add_argument('--secret', help='External secret from ejabberd\'s mod_http_upload', required=True)
    parser.add_argument('-s', '--sender', help='Sender', required=True)
    parser.add_argument('-r', '--recipient', help='Recipient')
    parser.add_argument('--puturl', help='ejabberd\'s put url', required=True)
    parser.add_argument('-a', '--apiurl', help='ejabberd\'s api url', required=True)
    parser.add_argument('filename', help='File to upload')
    if os.path.isfile(CONFIG_FILENAME):
        args=parser.parse_args(['@'+CONFIG_FILENAME]+sys.argv[1:])
    else:
        args=parser.parse_args()

    # create sender object
    ejSender=Ejsendf(args.user, args.password, args.secret, args.puturl, args.apiurl)

    # upload file
    geturl=ejSender.upload(args.sender, args.filename)
    print('File upload complete. geturl:\n{}'.format(geturl))

    if args.recipient:
        # send from sender to recipient
        ejSender.send(args.sender, args.recipient, geturl)
        print('File sent.')
