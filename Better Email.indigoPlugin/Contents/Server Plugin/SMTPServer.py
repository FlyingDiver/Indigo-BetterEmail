#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import ssl
import smtplib
import logging
from os.path import basename

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Charset
from email.header import Header

import indigo

def addheader(message, headername, headervalue):
    if len(headervalue) == 0:
        return message

    message[headername] = Header(headervalue, 'utf-8')
    return message

# SMTP specific class and methods
class SMTPServer(object):

    def __init__(self, device):
        self.logger = logging.getLogger("Plugin.SMTPServer")
        self.device = device
        self.smtpQ = Queue()
        self.pollCounter = 0  # check on first pass

    def __str__(self):
        return self.status

    def smtpSend(self, pluginAction):

        # Override python's weird assumption that utf-8 text should be encoded with
        # base64, and instead use quoted-printable.
        Charset.add_charset('utf-8', Charset.QP, Charset.QP, 'utf-8')

        self.logger.debug(u"Sending to SMTP Server: " + self.device.name)

        smtpDevice = indigo.devices[pluginAction.deviceId]
        smtpProps = smtpDevice.pluginProps

        if "emailTo" in pluginAction.props:
            emailTo = indigo.activePlugin.substitute(pluginAction.props["emailTo"])
        else:
            self.logger.error(u"No emailTo property in plugin property dict")
            return

        if "emailSubject" in pluginAction.props:
            emailSubject = indigo.activePlugin.substitute(pluginAction.props["emailSubject"])
        else:
            self.logger.error(u"No emailSubject property in plugin property dict")
            return

        if "emailMessage" in pluginAction.props:
            emailMessage = indigo.activePlugin.substitute(pluginAction.props["emailMessage"])
        else:
            self.logger.error(u"No emailMessage property in plugin property dict")
            return

        emailCC = indigo.activePlugin.substitute(pluginAction.props.get("emailCC", ""))
        emailBCC = indigo.activePlugin.substitute(pluginAction.props.get("emailBCC", ""))

        attach = pluginAction.props.get("emailAttachments", "")
        if len(attach) == 0:
            msg = MIMEText(emailMessage, 'plain', 'utf-8')
        else:
            msg = MIMEMultipart()
            msg.attach(MIMEText(emailMessage, 'plain', 'utf-8'))

            files = indigo.activePlugin.substitute(attach)
            fileList = files.split(",")
            for f in fileList:
                with open(f, "rb") as fil:
                    part = MIMEApplication(fil.read(), Name=basename(f))
                    part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
                    msg.attach(part)

        toAddresses = emailTo.split(",") + emailCC.split(",") + emailBCC.split(",")
        emailFrom = smtpProps["fromAddress"]

        msg = addheader(msg, 'From', emailFrom)
        msg = addheader(msg, 'Subject', emailSubject)
        msg = addheader(msg, 'To', emailTo)
        msg = addheader(msg, 'Cc', emailCC)
        msg = addheader(msg, 'Bcc', emailBCC)

        try:
            if smtpProps['encryptionType'] == 'SSL':
                connection = smtplib.SMTP_SSL(smtpProps['address'].encode('ascii', 'ignore'), int(smtpProps['hostPort']))
                connection.ehlo()
                connection.login(smtpProps["serverLogin"], smtpProps["serverPassword"])
                connection.sendmail(emailFrom, toAddresses, msg.as_string())
                connection.quit()

            elif smtpProps['encryptionType'] == 'StartTLS':
                connection = smtplib.SMTP(smtpProps['address'].encode('ascii', 'ignore'), int(smtpProps['hostPort']))
                connection.ehlo()
                connection.starttls()
                connection.ehlo()
                connection.login(smtpProps["serverLogin"], smtpProps["serverPassword"])
                connection.sendmail(emailFrom, toAddresses, msg.as_string())
                connection.quit()

            elif smtpProps['encryptionType'] == 'None':
                connection = smtplib.SMTP(smtpProps['address'].encode('ascii', 'ignore'), int(smtpProps['hostPort']))
                connection.ehlo()
                if (len(smtpProps["serverLogin"]) > 0) and (len(smtpProps["serverPassword"]) > 0):
                    connection.login(smtpProps["serverLogin"], smtpProps["serverPassword"])
                connection.sendmail(emailFrom, toAddresses, msg.as_string())
                connection.quit()

            else:
                self.logger.error(u"Unknown encryption type: " + smtpProps['encryptionType'])
                return False

        except Exception, e:
            self.logger.exception(self.device.name + u": SMTP server connection error: " + str(e))
            smtpDevice.updateStateOnServer(key="serverStatus", value="Failure")
            smtpDevice.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            return False

        else:

            smtpDevice.updateStateOnServer(key="serverStatus", value="Success")
            smtpDevice.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)

            broadcastDict = {'messageFrom': emailFrom, 'messageTo': toAddresses, 'messageSubject': emailSubject, 'messageText': emailMessage}
            indigo.server.broadcastToSubscribers(u"messageSent", broadcastDict)

            return True


    def pollCheck(self):
        counter = int(self.device.pluginProps['pollingFrequency'])
        if counter == 0:  # no polling for frequency = 0
            return False

        self.pollCounter -= 1
        if self.pollCounter <= 0:
            self.pollCounter = counter
            return True
        else:
            return False

    def poll(self):
        self.logger.debug(self.device.name + u": SMTP poll, " + str(self.smtpQ.qsize()) + u" items in queue")
        while not self.smtpQ.empty():
            action = self.smtpQ.get(False)
            if not self.smtpSend(action):
                self.smtpQ.put(action)  # put back in queue if sending fails
                return
