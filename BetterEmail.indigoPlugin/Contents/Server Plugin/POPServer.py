#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import time
import ssl
import poplib
import logging

from email.Parser import FeedParser
from email import Charset
from email.header import decode_header

#from Queue import Queue

import indigo

# POP specific class and methods
class POPServer(object):

    def __init__(self, device):
        self.logger = logging.getLogger("Plugin.POPServer")
        self.device = device
        self.popProps = self.device.pluginProps
        self.next_poll = time.time()


    def __str__(self):
        return self.status

    def shutDown(self):
        self.logger.debug(self.device.name + u": shutting down")

    def pollCheck(self):
        now = time.time()
        if now > self.next_poll:
            self.next_poll = now + float(self.popProps.get('pollingFrequency', "15")) * 60.0
            return True
        else:
            return False


    def poll(self):
        self.logger.debug(self.device.name + u": Connecting to POP Server")
        oldMessageList = indigo.activePlugin.pluginPrefs.get(u"readMessages", indigo.List())
        newMessageList = indigo.List()

        try:
            if self.popProps['encryptionType'] == 'SSL':
                connection = poplib.POP3_SSL(self.popProps['address'].encode('ascii', 'ignore'),
                                             int(self.popProps['hostPort']))
            elif self.popProps['encryptionType'] == 'None':
                connection = poplib.POP3(self.popProps['address'].encode('ascii', 'ignore'),
                                         int(self.popProps['hostPort']))
            else:
                self.logger.error(self.device.name + u": Unknown encryption type: " + self.popProps['encryptionType'])
                return

            connection.user(self.popProps['serverLogin'])
            connection.pass_(self.popProps['serverPassword'])
            (numMessages, totalSize) = connection.stat()
            if numMessages == 0:
                self.logger.debug(self.device.name + u": No messages to process")

            for i in range(numMessages):
                messageNum = i + 1
                self.logger.debug(self.device.name + u": Fetching Message # " + str(messageNum))
                try:
                    (server_msg, body, octets) = connection.retr(messageNum)
                    uidl = connection.uidl(messageNum).split()[2]
                    newMessageList.append(str(uidl))
                    if uidl in oldMessageList:
                        self.logger.debug(self.device.name + u": Message " + uidl + " already seen, skipping...")
                        continue

                    self.logger.debug(self.device.name + u": Parsing message " + uidl)
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
                        self.logger.info(self.device.name + u": Received Message Subject: " + messageSubject)
                    except Exception, e:
                        self.logger.error(self.device.name + u': Error decoding "Subject:" header: %s, error: %s' % (str(message.get("Subject")), str(e)))
                        messageSubject = ""

                    try:
                        bytes, encoding = decode_header(message.get("From"))[0]
                        if encoding:
                            messageFrom = bytes.decode(encoding)
                        else:
                            messageFrom = message.get("From")
                        self.logger.info(u"Received Message From: " + messageFrom)
                    except Exception, e:
                        self.logger.error(self.device.name + u': Error decoding "From:" header: %s, error: %s' % (str(message.get("From")), str(e)))
                        messageFrom = ""

                    try:
                        bytes, encoding = decode_header(message.get("To"))[0]
                        if encoding:
                            messageTo = bytes.decode(encoding)
                        else:
                            messageTo = message.get("To")
                        self.logger.info(self.device.name + u": Received Message To: " + messageTo)
                    except Exception, e:
                        self.logger.error(self.device.name + u': Error decoding "To:" header: %s, error: %s' % (str(message.get("To")), str(e)))
                        messageTo = ""

                    try:
                        bytes, encoding = decode_header(message.get("Date"))[0]
                        if encoding:
                            messageDate = bytes.decode(encoding)
                        else:
                            messageDate = message.get("Date")
                        self.logger.info(self.device.name + u": Received Message Date: " + messageDate)
                    except Exception, e:
                        self.logger.debug(self.device.name + 'Error decoding "Date:" "%s", error: %s' % (str(message.get("Date")), str(e)))
                        messageDate = ""

                    try:
                        if message.is_multipart():
                            self.logger.threaddebug(self.device.name + u": checkMsgs: Decoding multipart message")
                            for part in message.walk():
                                type = part.get_content_type()
                                self.logger.threaddebug('\tfound type: %s' % type)
                                if type == "text/plain":
                                    break
                            else:
                                raise Exception("No plain text segment found in multipart message")
                                
                            charset = part.get_content_charset()
                            if charset:
                                messageText = part.get_payload(decode=True).decode(charset)
                            else:
                                messageText = part.get_payload()
                        else:
                            charset = message.get_content_charset()
                            if charset:
                                messageText = message.get_payload(decode=True).decode(charset)
                            else:
                                messageText = message.get_payload()

                    except Exception, e:
                        self.logger.error(self.device.name + u': Error decoding Body of Message # ' + messageNum + ": " + str(e))
                        messageText = u""

                    stateList = [
                                {'key':'messageFrom',   'value':messageFrom},
                                {'key':'messageTo',     'value':messageTo},
                                {'key':'messageSubject','value':messageSubject},
                                {'key':'messageDate',   'value':messageDate},
                                {'key':'messageText',   'value':messageText},
                                {'key':'lastMessage',   'value':uidl}
                    ]
                    self.logger.threaddebug(self.device.name + u': checkMsgs: Updating states on server: %s' % str(stateList))
                    self.device.updateStatesOnServer(stateList)
                    broadcastDict = {'messageFrom': messageFrom, 'messageTo': messageTo, 'messageSubject': messageSubject, 'messageDate': messageDate, 'messageText': messageText}
                    indigo.server.broadcastToSubscribers(u"messageReceived", broadcastDict)
                    indigo.activePlugin.triggerCheck(self.device)

                    # If configured to do so, delete the message, otherwise mark it as processed
                    if self.popProps['delete']:
                        self.logger.debug(self.device.name + u": Deleting Message # " + str(messageNum))
                        connection.dele(messageNum)

                except Exception, e:
                    self.logger.error(self.device.name + u': Error fetching Message ' + str(messageNum) + ": " + str(e))
                    pass

            # close the connection and log out
            indigo.activePlugin.pluginPrefs[u"readMessages"] = newMessageList
            self.device.updateStateOnServer(key="serverStatus", value="Success")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
            connection.quit()
            self.logger.debug(self.device.name + u": Logged out from POP server")

        except Exception, e:
            self.logger.error(self.device.name + u": POP server connection error: " + str(e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            indigo.activePlugin.connErrorTriggerCheck(self.device)
            
