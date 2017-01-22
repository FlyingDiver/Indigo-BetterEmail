#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import ssl
import imaplib2
import logging

from email.Parser import Parser
from email import Charset
from email.header import decode_header

from Queue import Queue
from threading import Thread, Event

import indigo

# IMAP specific class and methods

class IMAPServer(object):

    def __init__(self, device):
        self.logger = logging.getLogger("Plugin.IMAPServer")
        self.device = device
        self.imapProps = self.device.pluginProps
        if self.imapProps['useIDLE']:
            self.connect()
            self.thread = Thread(target=self.idle)
            self.event = Event()
            self.thread.start()
        self.pollCounter = 0  # check on first pass

    def __del__(self, device):
        if self.imapProps['useIDLE']:
            self.event.set()
            self.connection.close()
            self.connection.logout()

    def __str__(self):
        return self.status

    def connect(self):
        try:
            if self.imapProps['encryptionType'] == 'SSL':
                self.logger.debug(self.device.name + u": Doing connect using encryptionType = " + self.imapProps['encryptionType'])
                self.connection = imaplib2.IMAP4_SSL(self.imapProps['address'].encode('ascii', 'ignore'), int(self.imapProps['hostPort']))
                self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
                self.connection.select("INBOX")

            elif self.imapProps['encryptionType'] == 'StartTLS':
                self.logger.debug(self.device.name + u": Doing connect using encryptionType = " + self.imapProps['encryptionType'])
                self.connection = imaplib2.IMAP4(self.imapProps['address'].encode('ascii', 'ignore'),int(self.imapProps['hostPort']))
                self.logger.debug(self.device.name + u": Doing starttls()")
                self.connection.starttls()
                self.logger.debug(self.device.name + u": Doing login()")
                self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
                self.logger.debug(self.device.name + u": Doing select(\"INBOX\")")
                self.connection.select("INBOX")

            elif self.imapProps['encryptionType'] == 'None':
                self.logger.debug(self.device.name + u": Doing connect using encryptionType = " + self.imapProps['encryptionType'])
                self.connection = imaplib2.IMAP4(self.imapProps['address'].encode('ascii', 'ignore'), int(self.imapProps['hostPort']))
                self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
                self.connection.select("INBOX")

            else:
                self.logger.error(u"Unknown encryption type: " + self.imapProps['encryptionType'])

        except Exception, e:
            self.logger.error(self.device.name + ': Error connecting to IMAP server: ' + str(e))
            raise

    def idle(self):
        self.logger.debug(self.device.name + u": idle() called")

        def callback(args):
            if not self.event.isSet():
                self.needsync = True
                self.event.set()

        while True:
            if self.event.isSet():
                self.logger.debug(self.device.name + u": IDLE Thread Exiting")
                return
            self.needsync = False

            self.connection.idle(callback=callback)
            self.event.wait()

            if self.needsync:
                self.event.clear()
                self.logger.debug(self.device.name + u": IDLE Event Received")
                self.checkMsgs()

    def checkMsgs(self):
        self.logger.debug(self.device.name + u": Doing checkMsgs")
        typ, msg_ids = self.connection.search(None, 'ALL')
        self.logger.debug(self.device.name + u": msg_ids = " + str(msg_ids))
        for messageNum in msg_ids[0].split():
            self.logger.debug(self.device.name + u": Checking Message # " + messageNum)
            try:
                typ, resp = self.connection.fetch(messageNum, '(FLAGS)')
                if "$IndigoProcessed" in resp[0]:
                    self.logger.debug(self.device.name + u": Message # " + messageNum + " already seen, skipping...")
                    continue
            except Exception, e:
                self.logger.error(self.device.name + ': Error fetching FLAGS for Message # ' + messageNum + ": " + str(e))
                pass

            try:
                self.logger.debug(self.device.name + u": Fetching Message # " + messageNum)
                typ, data = self.connection.fetch(messageNum, '(RFC822)')
                parser = Parser()
                message = parser.parsestr(data[0][1])
            except Exception, e:
                self.logger.error('Error fetching Message # ' + messageNum + ": " + str(e))
                pass

            try:
                bytes, encoding = decode_header(message.get("Subject"))[0]
                if encoding:
                    messageSubject = bytes.decode(encoding)
                else:
                    messageSubject = message.get("Subject")
                self.logger.debug(u"Received Message Subject: " + messageSubject)
            except Exception, e:
                self.logger.debug('Error decoding "Subject:" "%s", error: %s' % (str(message.get("Subject")), str(e)))
                messageSubject = ""

            try:
                bytes, encoding = decode_header(message.get("From"))[0]
                if encoding:
                    messageFrom = bytes.decode(encoding)
                else:
                    messageFrom = message.get("From")
                self.logger.debug(u"Received Message From: " + messageFrom)
            except Exception, e:
                self.logger.debug('Error decoding "From:" "%s", error: %s' % (str(message.get("From")), str(e)))
                messageFrom = ""

            try:
                bytes, encoding = decode_header(message.get("To"))[0]
                if encoding:
                    messageTo = bytes.decode(encoding)
                else:
                    messageTo = message.get("To")
                self.logger.debug(u"Received Message To: " + messageTo)
            except Exception, e:
                self.logger.debug('Error decoding "To:" "%s", error: %s' % (str(message.get("To")), str(e)))
                messageTo = ""

            try:
                messageID = message.get("Message-Id")
                self.logger.debug(u"Received Message ID: " + messageID)
            except Exception, e:
                self.logger.debug('Error decoding "Message-Id:" "%s", error: %s' % (str(message.get("Message-Id")), str(e)))
                messageID = ""

            try:
                if message.is_multipart():
                    part0 = message.get_payload(0)  # we only look at the first alternative content part
                    charset = part0.get_content_charset()
                    if charset:
                        messageText = part0.get_payload(decode=True).decode(charset)
                    else:
                        messageText = part0.get_payload()
                else:
                    charset = message.get_content_charset()
                    if charset:
                        messageText = message.get_payload(decode=True).decode(charset)
                    else:
                        messageText = message.get_payload()

            except Exception, e:
                self.logger.error('Error decoding Body of Message # ' + messageNum + ": " + str(e))
                messageText = u""

            stateList = [
                        {'key':'messageFrom',   'value':messageFrom},
                        {'key':'messageSubject','value':messageSubject},
                        {'key':'messageText',   'value':messageText},
                        {'key':'lastMessage',   'value':messageID}
            ]
            self.device.updateStatesOnServer(stateList)
            indigo.activePlugin.triggerCheck(self.device)
            broadcastDict = {'messageFrom': messageFrom, 'messageTo': messageTo, 'messageSubject': messageSubject, 'messageText': messageText}
            indigo.server.broadcastToSubscribers(u"messageReceived", broadcastDict)

            # If configured to do so, delete the message, otherwise mark it as processed
            if self.imapProps['delete']:
                self.logger.debug(u"Deleting message # " + messageNum)
                t, resp = self.connection.store(messageNum, '+FLAGS', r'(\Deleted)')
            else:
                # Mark the message as successfully processed
                t, resp = self.connection.store(messageNum, '+FLAGS', r'($IndigoProcessed)')

        self.connection.expunge()

    def pollCheck(self):
        if self.device.pluginProps['useIDLE']:  # skip poll when using IDLE
            return False

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
        if self.imapProps['useIDLE']:  # skip poll when using IDLE
            self.logger.debug(u"Skipping IMAP Server using IDLE: " + self.device.name)
            return

        self.logger.debug(u"Polling IMAP Server: " + self.device.name)

        try:
            self.connect()
            self.checkMsgs()

            # close the connection and log out
            self.device.updateStateOnServer(key="serverStatus", value="Success")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
            self.connection.close()
            self.connection.logout()
            self.logger.debug(u"Logged out from IMAP server: " + self.device.name)
        except Exception, e:
            self.logger.error(u"IMAP server connection error: " + str(e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
