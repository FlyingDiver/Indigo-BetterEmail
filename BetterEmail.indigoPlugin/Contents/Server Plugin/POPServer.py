#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import ssl
import poplib
import logging

from email.Parser import FeedParser
from email import Charset
from email.header import decode_header

from Queue import Queue

import indigo

# POP specific class and methods
class POPServer(object):

    def __init__(self, device):
        self.logger = logging.getLogger("Plugin.POPServer")
        self.device = device
        self.pollCounter = 0  # check on first pass

    def __str__(self):
        return self.status

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
        self.logger.debug(u"Connecting to POP Server: " + self.device.name)
        oldMessageList = indigo.activePlugin.pluginPrefs.get(u"readMessages", indigo.List())
        newMessageList = indigo.List()

        try:
            if self.device.pluginProps['encryptionType'] == 'SSL':
                connection = poplib.POP3_SSL(self.device.pluginProps['address'].encode('ascii', 'ignore'),
                                             int(self.device.pluginProps['hostPort']))
            elif self.device.pluginProps['encryptionType'] == 'None':
                connection = poplib.POP3(self.device.pluginProps['address'].encode('ascii', 'ignore'),
                                         int(self.device.pluginProps['hostPort']))
            else:
                self.logger.error(
                    u"Unknown encryption type: " + self.device.pluginProps['encryptionType'])
                return

            connection.user(self.device.pluginProps['serverLogin'])
            connection.pass_(self.device.pluginProps['serverPassword'])
            (numMessages, totalSize) = connection.stat()
            if numMessages == 0:
                self.logger.debug(u"No messages to process")

            for i in range(numMessages):
                messageNum = i + 1
                self.logger.debug(u"Retrieving Message # " + str(messageNum))
                try:
                    (server_msg, body, octets) = connection.retr(messageNum)
                    uidl = connection.uidl(messageNum).split()[2]
                    newMessageList.append(str(uidl))
                    if uidl in oldMessageList:
                        self.logger.debug(u"Message " + uidl + " already seen, skipping...")
                        continue

                    self.logger.debug(u"Parsing message " + uidl)
                    parser = FeedParser()
                    for line in body:
                        parser.feed(str(line + '\n'))
                    message = parser.close()

                    try:
                        bytes, encoding = decode_header(message.get("Subject"))[0]
                        if encoding:
                            messageSubject = bytes.decode(encoding)
                        else:
                            messageSubject = message.get("Subject")
                        self.logger.debug(u"Received Message Subject: " + messageSubject)
                    except Exception, e:
                        self.logger.error('Error decoding "Subject:" header: %s' %s str(e))
                        self.logger.error('Error decoding "Subject:" header: %s, error: %s' % (str(message.get("Subject")), str(e)))
                        messageSubject = ""

                    try:
                        bytes, encoding = decode_header(message.get("From"))[0]
                        if encoding:
                            messageFrom = bytes.decode(encoding)
                        else:
                            messageFrom = message.get("From")
                        self.logger.debug(u"Received Message From: " + messageFrom)
                    except Exception, e:
                        self.logger.error('Error decoding "From:" header: %s' %s str(e))
                        self.logger.error('Error decoding "From:" header: %s, error: %s' % (str(message.get("From")), str(e)))
                        messageFrom = ""

                    try:
                        bytes, encoding = decode_header(message.get("To"))[0]
                        if encoding:
                            messageTo = bytes.decode(encoding)
                        else:
                            messageTo = message.get("To")
                        self.logger.debug(u"Received Message To: " + messageTo)
                    except Exception, e:
                        self.logger.error('Error decoding "To:" header: %s' %s str(e))
                        self.logger.error('Error decoding "To:" header: %s, error: %s' % (str(message.get("To")), str(e)))
                        messageTo = ""

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
                                {'key':'lastMessage',   'value':uidl}
                    ]
                    self.device.updateStatesOnServer(stateList)
                    broadcastDict = {'messageFrom': messageFrom, 'messageTo': messageTo, 'messageSubject': messageSubject, 'messageText': messageText}
                    indigo.server.broadcastToSubscribers(u"messageReceived", broadcastDict)
                    indigo.activePlugin.triggerCheck(self.device)

                    # If configured to do so, delete the message, otherwise mark it as processed
                    if self.device.pluginProps['delete']:
                        self.logger.debug(u"Deleting Message # " + str(messageNum))
                        connection.dele(messageNum)

                except Exception, e:
                    self.logger.error('Error fetching Message ' + str(messageNum) + ": " + str(e))
                    pass

            # close the connection and log out
            indigo.activePlugin.pluginPrefs[u"readMessages"] = newMessageList
            self.device.updateStateOnServer(key="serverStatus", value="Success")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
            connection.quit()
            self.logger.debug(u"Logged out from POP server")

        except Exception, e:
            self.logger.error(u"POP server connection error: " + str(e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
