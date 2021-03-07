#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

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
        self.logger.debug(u"{}: shutting down".format(self.device.name))

    def pollCheck(self):
        now = time.time()
        if now > self.next_poll:
            self.next_poll = now + float(self.popProps.get('pollingFrequency', "15")) * 60.0
            return True
        else:
            return False


    def poll(self):
        self.logger.debug(u"{}: Connecting to POP Server".format(self.device.name))
        oldMessageList = indigo.activePlugin.pluginPrefs.get(u"readMessages-" + str(self.device.id), indigo.List())
        newMessageList = indigo.List()

        try:
            if self.popProps['encryptionType'] == 'SSL':
                connection = poplib.POP3_SSL(self.popProps['address'].encode('ascii', 'ignore'),
                                             int(self.popProps['hostPort']))
            elif self.popProps['encryptionType'] == 'None':
                connection = poplib.POP3(self.popProps['address'].encode('ascii', 'ignore'),
                                         int(self.popProps['hostPort']))
            else:
                self.logger.error(u"{}: Unknown encryptionType = {}".format(self.device.name, self.popProps['encryptionType']))
                return

            connection.user(self.popProps['serverLogin'])
            connection.pass_(self.popProps['serverPassword'])
            (numMessages, totalSize) = connection.stat()
            if numMessages == 0:
                self.logger.debug(u"{}: No messages to process".format(self.device.name))

            for i in range(numMessages):
                messageNum = i + 1
                self.logger.debug(u"{}: Fetching Message # {}".format(self.device.name, messageNum))
                try:
                    (server_msg, body, octets) = connection.retr(messageNum)
                    uidl = connection.uidl(messageNum).split()[2]
                    newMessageList.append(str(uidl))
                    if uidl in oldMessageList:
                        self.logger.debug(u"{}: Message {} already seen, skipping...".format(self.device.name, uidl))
                        continue

                    self.logger.debug(u"{}: Parsing message {}".format(self.device.name, uidl))
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
                        self.logger.debug(u"{}: Received Message Subject: ".format(self.device.name, messageSubject))
                    except Exception, e:
                        self.logger.error(u'{}: Error decoding "Subject:" "{}", error: {}'.format(self.device.name, message.get("Subject"), e))
                        messageSubject = ""

                    try:
                        bytes, encoding = decode_header(message.get("From"))[0]
                        if encoding:
                            messageFrom = bytes.decode(encoding)
                        else:
                            messageFrom = message.get("From")
                        self.logger.debug(u"{}: Received Message From: ".format(self.device.name, messageFrom))
                    except Exception, e:
                        self.logger.error(u'{}: Error decoding "From:" "{}", error: {}'.format(self.device.name, message.get("From"), e))
                        messageFrom = ""

                    try:
                        bytes, encoding = decode_header(message.get("To"))[0]
                        if encoding:
                            messageTo = bytes.decode(encoding)
                        else:
                            messageTo = message.get("To")
                        self.logger.debug(u"{}: Received Message To: ".format(self.device.name, messageTo))
                    except Exception, e:
                        self.logger.error(u'{}: Error decoding "To:" "{}", error: {}'.format(self.device.name, message.get("To"), e))
                        messageTo = ""

                    try:
                        bytes, encoding = decode_header(message.get("Date"))[0]
                        if encoding:
                            messageDate = bytes.decode(encoding)
                        else:
                            messageDate = message.get("Date")
                        self.logger.debug(u"{}: Received Message Date: ".format(self.device.name, messageDate))
                    except Exception, e:
                        self.logger.error(u'{}: Error decoding "Date:" "{}", error: {}'.format(self.device.name, message.get("Date"), e))
                        messageDate = ""

                    try:
                        if message.is_multipart():
                            self.logger.threaddebug( u"{}: checkMsgs: Decoding multipart message".format(self.device.name))
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
                        self.logger.error(u'{}: Error decoding Body of Message, error: {}'.format(self.device.name, e))
                        messageText = u""

                    stateList = [
                                {'key':'messageFrom',   'value':messageFrom},
                                {'key':'messageTo',     'value':messageTo},
                                {'key':'messageSubject','value':messageSubject},
                                {'key':'messageDate',   'value':messageDate},
                                {'key':'messageText',   'value':messageText},
                                {'key':'lastMessage',   'value':uidl}
                    ]
                    self.logger.threaddebug(u"{}: checkMsgs: Updating states on server: {}".format(self.device.name, str(stateList)))
                    self.device.updateStatesOnServer(stateList)
                    broadcastDict = {'messageFrom': messageFrom, 'messageTo': messageTo, 'messageSubject': messageSubject, 'messageDate': messageDate, 'messageText': messageText}
                    indigo.server.broadcastToSubscribers(u"messageReceived", broadcastDict)
                    indigo.activePlugin.triggerCheck(self.device)

                    # If configured to do so, delete the message, otherwise mark it as processed
                    if self.popProps['delete']:
                        self.logger.debug(u"{}: Deleting Message {}".format(self.device.name, messageNum))
                        connection.dele(messageNum)

                except Exception, e:
                    self.logger.error(u"{}: Error fetching Message {}: {}".format(self.device.name, messageNum, e))
                    pass

            # close the connection and log out
            indigo.activePlugin.pluginPrefs[u"readMessages-" + str(self.device.id)] = newMessageList
            self.device.updateStateOnServer(key="serverStatus", value="Success")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
            connection.quit()
            self.logger.debug(self.device.name + u": Logged out from POP server")

        except Exception, e:
            self.logger.error(u"{}: POP server connection error: {}".format(self.device.name, e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            indigo.activePlugin.connErrorTriggerCheck(self.device)
            
