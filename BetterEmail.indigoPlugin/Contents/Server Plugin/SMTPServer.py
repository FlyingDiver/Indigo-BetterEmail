#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import time
import ssl
import smtplib
import logging
from os.path import basename

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Charset
from email.header import Header
from email.utils import formatdate, make_msgid

from Queue import Queue

import indigo

def addheader(message, headername, headervalue, encode):
    if len(headervalue) == 0:
        return message

    if encode:
        message[headername] = Header(headervalue, 'utf-8')
    else:
        message[headername] = Header(headervalue, 'us-ascii')
    
    return message

# SMTP specific class and methods
class SMTPServer(object):

    def __init__(self, device):
        self.logger = logging.getLogger("Plugin.SMTPServer")
        self.device = device
        self.smtpProps = self.device.pluginProps
        self.smtpQ = Queue()
        self.next_poll = time.time()

    def __str__(self):
        return self.status

    def shutDown(self):
        self.logger.debug(u"{}: shutting down".format(self.device.name))

    def pollCheck(self):
        pollingFrequency = int(self.smtpProps.get('pollingFrequency', "15"))
        if pollingFrequency == 0:
            return False
            
        now = time.time()
        if now > self.next_poll:
            self.next_poll = now + float(pollingFrequency) * 60.0
            return True
        else:
            return False


    def poll(self):
        self.logger.debug(u"{}: SMTP poll, {} items in queue".format(self.device.name, self.smtpQ.qsize()))
        while not self.smtpQ.empty():
            propsDict = self.smtpQ.get(False)
            if not self.smtpSend(propsDict):
                self.smtpQ.put(propsDict)  # put back in queue if sending fails
                return

    def clearQueue(self):
        self.smtpQ = Queue()  # just nuke the old queue and replace it

    def smtpSend(self, propsDict):

        # Override python's weird assumption that utf-8 text should be encoded with
        # base64, and instead use quoted-printable.
        Charset.add_charset('utf-8', Charset.QP, Charset.QP, 'utf-8')

        if "emailTo" in propsDict:
            emailTo = indigo.activePlugin.substitute(propsDict["emailTo"])
        else:
            self.logger.error(u"{}: No emailTo property in plugin property dict".format(self.device.name))
            return

        if "emailSubject" in propsDict:
            emailSubject = indigo.activePlugin.substitute(propsDict["emailSubject"])
        else:
            self.logger.error(u"{}: No emailSubject property in plugin property dict".format(self.device.name))
            return

        if "emailMessage" in propsDict:
            emailMessage = indigo.activePlugin.substitute(propsDict["emailMessage"])
        else:
            self.logger.error(u"{}: No emailMessage property in plugin property dict".format(self.device.name))
            return

        emailCC = indigo.activePlugin.substitute(propsDict.get("emailCC", ""))
        emailBCC = indigo.activePlugin.substitute(propsDict.get("emailBCC", ""))
        
        emailFormat = propsDict.get("emailFormat", "plain")

        attach = propsDict.get("emailAttachments", "")
        if len(attach) == 0:
            msg = MIMEText(emailMessage, emailFormat, 'utf-8')
        else:
            msg = MIMEMultipart()
            msg.attach(MIMEText(emailMessage, emailFormat, 'utf-8'))

            files = indigo.activePlugin.substitute(attach)
            fileList = files.split(",")
            for f in fileList:
                with open(f, "rb") as fil:
                    part = MIMEApplication(fil.read(), Name=basename(f))
                    part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
                    msg.attach(part)

        toAddresses = emailTo.split(",") + emailCC.split(",") + emailBCC.split(",")
        emailFrom = self.smtpProps["fromAddress"]

        msg = addheader(msg, 'From', emailFrom, True)
        msg = addheader(msg, 'Subject', emailSubject, True)
        msg = addheader(msg, 'To', emailTo, True)
        msg = addheader(msg, 'Cc', emailCC, True)
        msg = addheader(msg, 'Bcc', emailBCC, True)
        msg = addheader(msg, 'Date', formatdate(localtime=True), False)
        msg = addheader(msg, 'Message-ID', make_msgid(), False)
        
        self.logger.info(u"{}: Sending email '{}' to '{}'".format(self.device.name, emailSubject, emailTo))

        try:
            if self.smtpProps['encryptionType'] == 'SSL':
                connection = smtplib.SMTP_SSL(self.smtpProps['address'].encode('ascii', 'ignore'), int(self.smtpProps['hostPort']))
                connection.ehlo()
                connection.login(self.smtpProps["serverLogin"].encode('ascii', 'ignore'), self.smtpProps["serverPassword"].encode('ascii', 'ignore'))
                connection.sendmail(emailFrom, toAddresses, msg.as_string())
                connection.quit()

            elif self.smtpProps['encryptionType'] == 'StartTLS':
                connection = smtplib.SMTP(self.smtpProps['address'].encode('ascii', 'ignore'), int(self.smtpProps['hostPort']))
                connection.ehlo()
                connection.starttls()
                connection.ehlo()
                connection.login(self.smtpProps["serverLogin"].encode('ascii', 'ignore'), self.smtpProps["serverPassword"].encode('ascii', 'ignore'))
                connection.sendmail(emailFrom, toAddresses, msg.as_string())
                connection.quit()

            elif self.smtpProps['encryptionType'] == 'None':
                connection = smtplib.SMTP(self.smtpProps['address'].encode('ascii', 'ignore'), int(self.smtpProps['hostPort']))
                connection.ehlo()
                if (len(self.smtpProps["serverLogin"]) > 0) and (len(self.smtpProps["serverPassword"]) > 0):
                    connection.login(self.smtpProps["serverLogin"].encode('ascii', 'ignore'), self.smtpProps["serverPassword"].encode('ascii', 'ignore'))
                connection.sendmail(emailFrom, toAddresses, msg.as_string())
                connection.quit()

            else:
                self.logger.error(u"Unknown encryption type: " + self.smtpProps['encryptionType'])
                return False

        except Exception, e:
            self.logger.error(u"{}: SMTP server connection error: {}".format(self.device.name, e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            indigo.activePlugin.connErrorTriggerCheck(self.device)
            return False

        else:

            self.device.updateStateOnServer(key="serverStatus", value="Success")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)

            broadcastDict = {'messageFrom': emailFrom, 'messageTo': toAddresses, 'messageSubject': emailSubject, 'messageText': emailMessage}
            indigo.server.broadcastToSubscribers(u"messageSent", broadcastDict)

            return True


