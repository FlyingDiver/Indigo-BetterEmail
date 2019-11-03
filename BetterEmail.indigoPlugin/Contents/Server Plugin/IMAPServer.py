#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import ssl
import time
import imaplib2
import logging

from email.Parser import Parser
from email import Charset
from email.header import decode_header

#from Queue import Queue
from threading import Thread, Event, Lock

import indigo

# IMAP specific class and methods

class IMAPServer(object):

    def __init__(self, device):
        self.logger = logging.getLogger("Plugin.IMAPServer")
        self.device = device
        self.imapProps = self.device.pluginProps
        self.logger.debug(u"{}: Creating IMAP Server".format(self.device.name))

        if self.imapProps['useIDLE']:
            self.logger.debug(u"{}: Using IMAP IDLE".format(self.device.name))
            self.connectionLock = Lock()
            self.idleLoopEvent = Event()
            self.lastIDLE = time.time()
            self.connectIMAP()
            self.needsync = False
            self.exitIDLE = False
            self.idleThread = Thread(target=self.idleIMAPThread)
            self.idleThread.start()
        else:
            self.next_poll = time.time() + float(self.imapProps.get('pollingFrequency', "15")) * 60.0

    def __str__(self):
        return self.status

    def shutDown(self):
        self.logger.debug(u"{}: shutting down".format(self.device.name))
        if self.imapProps['useIDLE']:
            try:
                self.logger.debug(u"{}: Stopping IDLE connection".format(self.device.name))
                self.exitIDLE = True
                self.idleLoopEvent.set()
                self.connection.close()
                self.connection.logout()
            except Exception, e:
                self.logger.error(u"{}: IMAP IDLE server shutdown error: {}".format(self.device.name, e))
                indigo.activePlugin.connErrorTriggerCheck(self.device)
            
    def pollCheck(self):

        if self.imapProps['useIDLE']:

            if time.time() > (self.lastIDLE + 3600.0):      # if we go an hour without an IDLE event, reconnect
                self.logger.warning(u"{}: IDLE Event Timeout, reconnecting".format(self.device.name))                
                indigo.activePlugin.restartQueue.put(self.device.id)
                                                
            if self.needsync:
                self.needsync= False
                return True
            else:
                return False
        
        # not IDLE, do normal poll check
        else:              
            if time.time() > self.next_poll:
                self.next_poll = time.time() + float(self.imapProps.get('pollingFrequency', "15")) * 60.0
                return True
            else:
                return False

    def poll(self):
        self.logger.debug(u"{}: Polling IMAP Server".format(self.device.name))

        if self.imapProps['useIDLE']:
            with self.connectionLock:
                try:
                    self.checkMsgs()
                except Exception, e:
                    self.logger.error(u"{}: IMAP checkMsgs error: {}".format(self.device.name, e))
                    
            return

        try:
            self.connectIMAP()
            self.checkMsgs()

            # close the connection and log out
            self.connection.close()
            self.connection.logout()
            self.logger.debug(u"{}: Logged out from IMAP server: ".format(self.device.name))
            
        except Exception, e:
            self.logger.error(u"{}: IMAP server connection error: {}".format(self.device.name, e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            
            
    def connectIMAP(self):
        try:
            self.logger.debug(u"{}: Doing connect using encryptionType = {}".format(self.device.name, self.imapProps['encryptionType']))
            if self.imapProps['encryptionType'] == 'SSL':
                self.connection = imaplib2.IMAP4_SSL(self.imapProps['address'].encode('ascii', 'ignore'), int(self.imapProps['hostPort']))

            elif self.imapProps['encryptionType'] == 'StartTLS':
                self.connection = imaplib2.IMAP4(self.imapProps['address'].encode('ascii', 'ignore'),int(self.imapProps['hostPort']))
                self.logger.debug(self.device.name + u": Doing starttls()")
                self.connection.starttls()

            elif self.imapProps['encryptionType'] == 'None':
                self.connection = imaplib2.IMAP4(self.imapProps['address'].encode('ascii', 'ignore'), int(self.imapProps['hostPort']))

            else:
                self.logger.error(u"{}: Unknown encryptionType = {}".format(self.device.name, self.imapProps['encryptionType']))
                self.connection = None
                return

            self.logger.debug(u"{}: Doing login()".format(self.device.name))
            self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
            self.logger.debug(u"{}: Doing select()".format(self.device.name))
            self.connection.select("INBOX")
            self.device.updateStateOnServer(key="serverStatus", value="Success")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
            resp, data = self.connection.list()
            if resp == 'OK':
                self.logger.threaddebug(u"{}: Mailbox list:".format(self.device.name))
                for mbox in data:
                    self.logger.threaddebug(u"{}:    Mailbox: {}".format(self.device.name, mbox))
                
            else:
                self.logger.error('{}: Error getting IMAP mailbox list: '.format(self.device.name))
                      
        except Exception, e:
            self.logger.error('{}: Error connecting to IMAP server: {}'.format(self.device.name, e))
            self.device.updateStateOnServer(key="serverStatus", value="Failure")
            self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            indigo.activePlugin.connErrorTriggerCheck(self.device)
            raise

    ##########################################################################################
    # run IDLE loop in separate thread.  When this function exits, the IDLE thread terminates

    def idleIMAPThread(self):
        self.logger.debug(u"{}: idleIMAPThread() called".format(self.device.name))

        def idleEvent(args):
            self.logger.debug(u"{}: IDLE Event Received".format(self.device.name))
            self.lastIDLE = time.time()
            if not self.exitIDLE and not self.connectionLock.locked():
                self.needsync = True
            self.idleLoopEvent.set()

        while True:

            self.connection.idle(callback=idleEvent)
            self.idleLoopEvent.wait()
            self.idleLoopEvent.clear()

            if self.exitIDLE:
                self.logger.debug(u"{}: IDLE Thread Exiting".format(self.device.name))
                return
    
    ##########################################################################################

    def checkMsgs(self):
        
        self.logger.debug(u"{}: Doing checkMsgs".format(self.device.name))
        typ, msg_ids = self.connection.search(None, 'ALL')
        self.logger.debug(u"{}: checkMsgs - typ = {}, msg_ids = {}".format(self.device.name, typ, msg_ids))
        if msg_ids == None or msg_ids[0] == None or msg_ids[0] == '':
            self.logger.debug(u"{}: checkMsgs - No messages".format(self.device.name))
            return
            
        for messageNum in msg_ids[0].split():
            
            if not self.imapProps['checkSeen']:         # only check for IndigoProcessed flag if we're not processing all messages
                try:
                    typ, resp = self.connection.fetch(messageNum, '(FLAGS)')
                    self.logger.threaddebug(u"{}: Message # {} Flags = '{}'".format(self.device.name, messageNum, resp))
                    if not resp:
                        self.logger.debug(u"{}: Message # {} has no Flags.  Processing anyway.".format(self.device.name, messageNum))
                    elif "$IndigoProcessed" in resp[0]:
                        self.logger.debug(u"{}: Message # {} already seen, skipping...".format(self.device.name, messageNum))
                        continue
                except Exception, e:
                    self.logger.error(u"{}: Error fetching FLAGS for Message # {}: {}".format(self.device.name, messageNum, e))
                    continue
                    
            try:
                self.logger.debug(u"{}: Fetching Message # {}".format(self.device.name, messageNum))
                typ, data = self.connection.fetch(messageNum, '(RFC822 BODY[])')
                parser = Parser()
                message = parser.parsestr(data[0][1])
                self.logger.debug(u"{}: Fetching Message # {} Complete".format(self.device.name, messageNum))
            except Exception, e:
                self.logger.error(u"{}: Error fetching Message # {}: {}".format(self.device.name, messageNum, e))
                continue

            try:
                bytes, encoding = decode_header(message.get("Subject"))[0]
                if encoding:
                    messageSubject = bytes.decode(encoding)
                else:
                    messageSubject = message.get("Subject")
                self.logger.debug(u"{}: Received Message Subject: {}".format(self.device.name, messageSubject))
            except Exception, e:
                self.logger.error(u'{}: Error decoding "Subject:" "{}", error: {}'.format(self.device.name, message.get("Subject"), e))
                messageSubject = ""

            try:
                bytes, encoding = decode_header(message.get("From"))[0]
                if encoding:
                    messageFrom = bytes.decode(encoding)
                else:
                    messageFrom = message.get("From")
                self.logger.debug(u"{}: Received Message From: {}".format(self.device.name, messageFrom))
            except Exception, e:
                self.logger.error(u'{}: Error decoding "From:" "{}", error: {}'.format(self.device.name, message.get("From"), e))
                messageFrom = ""

            try:
                bytes, encoding = decode_header(message.get("To"))[0]
                if encoding:
                    messageTo = bytes.decode(encoding)
                else:
                    messageTo = message.get("To")
                self.logger.debug(u"{}: Received Message To: {}".format(self.device.name, messageTo))
            except Exception, e:
                self.logger.error(u'{}: Error decoding "To:" "{}", error: {}'.format(self.device.name, message.get("To"), e))
                messageTo = ""

            try:
                bytes, encoding = decode_header(message.get("Date"))[0]
                if encoding:
                    messageDate = bytes.decode(encoding)
                else:
                    messageDate = message.get("Date")
                self.logger.debug(u"{}: Received Message Date: {}".format(self.device.name, messageDate))
            except Exception, e:
                self.logger.error(u'{}: Error decoding "Date:" "{}", error: {}'.format(self.device.name, message.get("Date"), e))
                messageDate = ""

            try:
                messageID = message.get("Message-Id")
                self.logger.debug(u"{}: Received Message ID: {}".format(self.device.name, messageID))
            except Exception, e:
                messageID = ""

            try:
                if message.is_multipart():
                    self.logger.threaddebug( u"{}: checkMsgs: Decoding multipart message".format(self.device.name))
                    
                    # look for text/plain or text/html, with text/plain preferred (break after finding plain type)
                    
                    use_part = None
                    for part in message.walk():
                        type = part.get_content_type()
                        self.logger.threaddebug('\tfound type: %s' % type)
                        if type == "text/plain":
                            use_part = part
                            break
                        elif type == "text/html":
                            use_part = part
                            
                    else:
                        if not use_part:
                            raise Exception("No searchable text segment found in multipart message")

                    charset = use_part.get_content_charset()
                    if charset:
                        messageText = use_part.get_payload(decode=True).decode(charset)
                    else:
                        messageText = use_part.get_payload()
                else:
                    self.logger.threaddebug( u"{}: checkMsgs: Decoding simple message".format(self.device.name))
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
                        {'key':'lastMessage',   'value':messageID}
            ]
            self.device.updateStatesOnServer(stateList)
            
            indigo.activePlugin.triggerCheck(self.device)
            
            broadcastDict = {'messageFrom': messageFrom, 'messageTo': messageTo, 'messageSubject': messageSubject, 'messageDate': messageDate, 'messageText': messageText}
            indigo.server.broadcastToSubscribers(u"messageReceived", broadcastDict)

            # Delete the message, move the message, or otherwise mark it as processed
            if self.imapProps['postProcess'] == 'delete':
                self.logger.debug(u"{}: Deleting message # {}".format(self.device.name, messageNum))
                t, resp = self.connection.store(messageNum, '+FLAGS', r'(\Deleted)')
            else:
                # Mark the message as successfully processed
                t, resp = self.connection.store(messageNum, '+FLAGS', r'($IndigoProcessed)')

                if self.imapProps['postProcess'] == 'move':
                    self.logger.debug(u"{}: Copying message # {} to {}".format(self.device.name, messageNum, self.imapProps['moveFolder']))
                    result = self.connection.copy(messageNum, self.imapProps['moveFolder'])
                    if result[0] == 'OK':
                        self.logger.debug(u"{}: Deleting message # {}".format(self.device.name, messageNum))
                        t, resp = self.connection.store(messageNum, '+FLAGS', r'(\Deleted)')
                    else:
                        self.logger.error(u"{}: Error moving message # {}: {}".format(self.device.name, messageNum, result))
                

        self.connection.expunge()
        self.logger.debug(u"{}: checkMsgs complete".format(self.device.name))
