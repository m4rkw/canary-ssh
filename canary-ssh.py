#!/usr/bin/env python3

import os
import sys
import yaml
import re
import hashlib
import smtplib
import time
import glob

DEFAULT_CONFIG_FILE = '/etc/canary-ssh.yaml'

class SSHCanary:

  def __init__(self):
    self.load_config()

    if not os.path.exists(self.config['data_path']):
      os.mkdir(self.config['data_path'])

    self.cleanup()
    self.monitor()


  def load_config(self):
    self.config = yaml.load(open(DEFAULT_CONFIG_FILE).read(), yaml.FullLoader)

    self.fingerprints = {}

    for key in self.config['fingerprints']:
      self.fingerprints[key['id']] = key['label']


  def monitor(self):
    offset = 0

    self.ip_map = {}
    self.user_map = {}

    start = time.time()

    while 1:
      fs = os.stat(self.config['log_file']).st_size

      if fs > offset:
        self.process_log(offset, fs)
        offset = fs
      elif fs < offset:
        if fs >0:
          self.process_log(0, fs)
        offset = fs

      time.sleep(0.1)

      if time.time() - start > 86400:
        self.cleanup()
        start = 0


  def process_log(self, _from, _to):
    fp = open(self.config['log_file'])
    fp.seek(_from)
    data = fp.read(_to - _from)
    fp.close()

    for line in data.split("\n"):
      self.process_line(line)


  def process_line(self, line):
    match = re.match('^.*?sshd\[([\d]+)\]:.*?Connection from (.*?) ', line)

    if match:
      pid = int(match.group(1))
      ip = match.group(2)

      self.ip_map[pid] = ip

    match = re.match('^.*?sshd\[([\d]+)\]:.*?userauth-request for user (.*?) ', line)

    if match:
      pid = int(match.group(1))
      user = match.group(2)

      self.user_map[pid] = user

    match = re.match('^.*?sshd\[([\d]+)\]:.*?userauth_pubkey: test pkalg (.*?) pkblob (.*?) (.*?) \[preauth\]', line)

    if match:
      pid = int(match.group(1))
      key_algo = match.group(2)
      key_type = match.group(3)
      key_blob = match.group(4)

      if key_blob in self.fingerprints:
        h = hashlib.sha256(line.encode('utf-8')).hexdigest()

        if not os.path.exists(self.config['data_path'] + '/' + h):
          ip = self.ip_map[pid]
          user = self.user_map[pid]

          message = "Subject: SSH key %s used!\n" % (self.fingerprints[key_blob])
          message += "From: %s\n" % (self.config['email_from'])
          message += "To: %s\n\n" % (self.config['email_to'])
          message += "user: %s\n" % (user)
          message += "ip: %s\n\n%s\n" % (ip, line)

          if self.config['smtp_ssl']:
            smtp_server = smtplib.SMTP_SSL(self.config['smtp_host'], self.config['smtp_port'])
          else:
            smtp_server = smtplib.SMTP(self.config['smtp_host'], self.config['smtp_port'])

          if self.config['starttls']:
            smtp_server.starttls()

          resp = smtp_server.sendmail(self.config['email_from'], self.config['email_to'], message)
          smtp_server.close()

          with open(self.config['data_path'] + '/' + h, 'w') as f:
            f.write(line)


  def cleanup(self):
    lines = {}

    for fn in glob.glob(self.config['data_path'] + '/*'):
      lines[open(fn).read()] = fn

    with open(self.config['log_file']) as f:
      for line in f:
        line = line.rstrip()

        if line in lines:
          lines.pop(line)

    for fn in lines:
      os.remove(fn)


SSHCanary()
