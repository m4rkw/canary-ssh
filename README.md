# Canary SSH

## What is it?

A simple python script that continuously monitors the sshd log on a system
looking for authentication attempts with specific ssh keys. If such are found it
sends an email alert.

## Why?

This was inspired by (but is in no way affiliated with) Thinkst Canary who
make awesome honeypot tools. They also offer free "canary tokens" here:
https://canarytokens.org/generate but don't currently offer ssh canary tokens so
I decided to roll iy own.

## How it works

If we set the LogLevel in sshd to DEBUG it will log key fingerprints that were
attempted for authentication. The script simply monitors the log and collates
these events, determines the connecting ip address and the username that was
attempted with the key and then sends these as alerts to the configured email
address.

It keeps track of log lines that were already processed so as not to alert again
if the service is restarted.

## Installation

0. Set LogLevel to DEBUG in sshd\_config:

````
# echo 'LogLevel DEBUG' >> /etc/ssh/sshd_config
# systemctl restart ssh
````

This is so that we can see key fingerprints in authentication attempts.

1. Generate your canary ssh keys:

````
$ ssh-keygen
````

2. Get the fingerprint of the private key:

````
$ ssh-keygen -l -f ~/.ssh/id_rsa
3072 SHA256:boaw1iequ0ahghaexieCh7nie5aiPahje9hohTau3oh user@machine (RSA)
````

3. Copy canary-ssh.py to /usr/local/bin/

````
$ sudo cp canary-ssh.py /usr/local/bin/
````

4. Create /etc/canary-ssh.yaml

````
---
log_file: /var/log/auth.log
data_path: /var/lib/ssh-canary
fingerprints:
- id: SHA256:boaw1iequ0ahghaexieCh7nie5aiPahje9hohTau3oh
  label: laptop
smtp_host: localhost
smtp_port: 25
smtp_ssl: false
smtp_starttls: false
email_from: me@mydomain.com
email_to: me@mydomain.com
````

Add your key fingerprints to the list with a label that will help you see which
key was used when an alert is fired.

5. Create a systemd unit for canary-ssh:

/etc/systemd/system/canary-ssh.service
````
[Unit]
Description=canary-ssh
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/local/bin/canary-ssh.py
Restart=always

[Install]
WantedBy=multi-user.target
````

6. Enable and start the service

````
# systemctl enable canary-ssh
# systemctl start canary-ssh
````
