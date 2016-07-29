#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import re
import ssl
import smtplib
import poplib
import imaplib2
import time
import logging
from os.path import basename

from email.Parser import Parser, FeedParser
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Charset
from email.header import Header, decode_header

from Queue import Queue
from threading import Thread, Event

from ghpu import GitHubPluginUpdater

kCurDevVersCount = 3  # current version of plugin devices


################################################################################
class Plugin(indigo.PluginBase):
    ########################################
    # Email Server Classes and Methods
    ########################################

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
                self.logger.exception(self.device.name + ': Error connecting to IMAP server: ' + str(e))
                raise

        def idle(self):
            self.logger.debug(self.device.name + u": idle() called")

            def callback(args):
                if not self.event.isSet():
                    self.needsync = True
                    self.event.set()

            while True:
                if self.event.isSet():
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
                    self.logger.exception(self.device.name + ': Error fetching FLAGS for Message # ' + messageNum + ": " + str(e))
                    pass

                try:
                    self.logger.debug(self.device.name + u": Fetching Message # " + messageNum)
                    typ, data = self.connection.fetch(messageNum, '(RFC822)')
                    parser = Parser()
                    message = parser.parsestr(data[0][1])
                except Exception, e:
                    self.logger.exception('Error fetching Message # ' + messageNum + ": " + str(e))
                    pass

                bytes, encoding = decode_header(message.get("Subject"))[0]
                if encoding:
                    messageSubject = bytes.decode(encoding)
                else:
                    messageSubject = message.get("Subject")
                self.logger.debug(u"Received Message Subject: " + messageSubject)

                bytes, encoding = decode_header(message.get("From"))[0]
                if encoding:
                    messageFrom = bytes.decode(encoding)
                else:
                    messageFrom = message.get("From")
                self.logger.debug(u"Received Message From: " + messageFrom)

                bytes, encoding = decode_header(message.get("To"))[0]
                if encoding:
                    messageTo = bytes.decode(encoding)
                else:
                    messageTo = message.get("To")
                self.logger.debug(u"Received Message To: " + messageTo)

                messageID = message.get("Message-Id")
                self.logger.debug(u"Received Message ID: " + messageID)

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
                    self.logger.exception('Error decoding Body of Message # ' + messageNum + ": " + str(e))
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
                self.logger.exception(u"IMAP server connection error: " + str(e))
                self.device.updateStateOnServer(key="serverStatus", value="Failure")
                self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)

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

                        bytes, encoding = decode_header(message.get("Subject"))[0]
                        if encoding:
                            messageSubject = bytes.decode(encoding)
                        else:
                            messageSubject = message.get("Subject")
                        self.logger.debug(u"Received Message Subject: " + messageSubject)

                        bytes, encoding = decode_header(message.get("From"))[0]
                        if encoding:
                            messageFrom = bytes.decode(encoding)
                        else:
                            messageFrom = message.get("From")
                        self.logger.debug(u"Received Message From: " + messageFrom)

                        bytes, encoding = decode_header(message.get("To"))[0]
                        if encoding:
                            messageTo = bytes.decode(encoding)
                        else:
                            messageTo = message.get("To")
                        self.logger.debug(u"Received Message To: " + messageTo)

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
                            self.logger.exception('Error decoding Body of Message # ' + messageNum + ": " + str(e))
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
                        self.logger.exception('Error fetching Message ' + str(messageNum) + ": " + str(e))
                        pass

                # close the connection and log out
                indigo.activePlugin.pluginPrefs[u"readMessages"] = newMessageList
                self.device.updateStateOnServer(key="serverStatus", value="Success")
                self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
                connection.quit()
                self.logger.debug(u"Logged out from POP server")

            except Exception, e:
                self.logger.exception(u"POP server connection error: " + str(e))
                self.device.updateStateOnServer(key="serverStatus", value="Failure")
                self.device.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)

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

            def addheader(message, headername, headervalue):
                if len(headervalue) == 0:
                    return message

                message[headername] = Header(headervalue, 'utf-8')
                return message

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

    ########################################
    # Main Plugin methods
    ########################################
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)

        try:
            self.logLevel = int(self.pluginPrefs[u"logLevel"])
        except:
            self.logLevel = logging.INFO
        self.indigo_log_handler.setLevel(self.logLevel)
        self.logger.debug(u"logLevel = " + str(self.logLevel))

    def __del__(self):
        indigo.PluginBase.__del__(self)

    def startup(self):
        self.logger.info(u"Starting Better Email")

        self.updater = GitHubPluginUpdater(self)
        self.updater.checkForUpdate()
        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', 24)) * 60.0 * 60.0
        self.logger.debug(u"updateFrequency = " + str(self.updateFrequency))
        self.next_update_check = time.time()

        self.serverDict = dict()  # IMAP/POP servers to poll
        self.triggers = {}

    def shutdown(self):
        self.logger.info(u"Shutting down Better Email")

    ####################

    def getDeviceConfigUiValues(self, pluginProps, typeId, devId):
        self.logger.debug("getDeviceConfigUiValues, typeID = " + typeId)
        valuesDict = indigo.Dict(pluginProps)
        errorsDict = indigo.Dict()

        if len(valuesDict) == 0:
            self.logger.debug("getDeviceConfigUiValues: no values, populating encryptionType and hostPort")
            if typeId == "imapAccount":
                valuesDict["encryptionType"] = "SSL"
                valuesDict["hostPort"] = "993"
            elif typeId == "popAccount":
                valuesDict["encryptionType"] = "SSL"
                valuesDict["hostPort"] = "995"
            elif typeId == "smtpAccount":
                valuesDict["encryptionType"] = "SSL"
                valuesDict["hostPort"] = "465"
        else:
            self.logger.debug("getDeviceConfigUiValues: no change, already populated")

        return (valuesDict, errorsDict)

    def listEncryptionTypes(self, filter=u'', valuesDict=None, typeId=u'', targetId=0):
        encryptionTypes = []
        if filter == "imapAccount":
            encryptionTypes = [("SSL", "SSL"), ("None", "None")]
        elif filter == "popAccount":
            encryptionTypes = [("SSL", "SSL"), ("None", "None")]
        elif filter == "smtpAccount":
            encryptionTypes = [("SSL", "SSL"), ("StartTLS", "StartTLS"), ("None", "None")]
        return encryptionTypes

    def encryptionSelected(self, valuesDict=None, filter=u'', typeId=u'', targetId=0):
        encryptionType = valuesDict.get(u'encryptionType', u'')
        if filter == "imapAccount":
            if encryptionType == "None":
                valuesDict['hostPort'] = 143
            elif encryptionType == "SSL":
                valuesDict['hostPort'] = 993
        elif filter == "popAccount":
            if encryptionType == "None":
                valuesDict['hostPort'] = 110
            elif encryptionType == "SSL":
                valuesDict['hostPort'] = 995
        elif filter == "smtpAccount":
            if encryptionType == "None":
                valuesDict['hostPort'] = 587
            elif encryptionType == "SSL":
                valuesDict['hostPort'] = 465
            elif encryptionType == "StartTLS":
                valuesDict['hostPort'] = 587
        return valuesDict

    ####################

    def triggerStartProcessing(self, trigger):
        self.logger.debug("Adding Trigger %s (%d)" % (trigger.name, trigger.id))
        assert trigger.id not in self.triggers
        self.triggers[trigger.id] = trigger

    def triggerStopProcessing(self, trigger):
        self.logger.debug("Removing Trigger %s (%d)" % (trigger.name, trigger.id))
        assert trigger.id in self.triggers
        del self.triggers[trigger.id]

    def triggerCheck(self, device):
        self.logger.debug("Checking Triggers for Device %s (%d)" % (device.name, device.id))

        for triggerId, trigger in sorted(self.triggers.iteritems()):
            self.logger.debug("\tChecking Trigger %s (%d), %s" % (trigger.name, trigger.id, trigger.pluginTypeId))

            if trigger.pluginProps["serverID"] != str(device.id):
                self.logger.debug("\t\tSkipping Trigger %s (%s), wrong device: %s" % (trigger.name, trigger.id, device.id))
            else:
                if trigger.pluginTypeId == "regexMatch":
                    field = trigger.pluginProps["fieldPopUp"]
                    pattern = trigger.pluginProps["regexPattern"]
                    self.logger.debug("\tChecking Device State %s for Pattern: %s" % (field, pattern))
                    cPattern = re.compile(pattern)
                    match = cPattern.search(device.states[field])
                    if match:
                        regexMatch = match.group()
                        self.logger.debug("\tExecuting Trigger %s (%d), match: %s" % (trigger.name, trigger.id, regexMatch))
                        device.updateStateOnServer(key="regexMatch", value=regexMatch)
                        indigo.trigger.execute(trigger)
                    else:
                        self.logger.debug("\tNo Match for Trigger %s (%d)" % (trigger.name, trigger.id))
                elif trigger.pluginTypeId == "stringMatch":
                    field = trigger.pluginProps["fieldPopUp"]
                    pattern = trigger.pluginProps["stringPattern"]
                    self.logger.debug("\tChecking Device State %s for string: %s" % (field, pattern))
                    if device.states[field] == pattern:
                        self.logger.debug("\tExecuting Trigger %s (%d)" % (trigger.name, trigger.id))
                        indigo.trigger.execute(trigger)
                    else:
                        self.logger.debug("\tNo Match for Trigger %s (%d)" % (trigger.name, trigger.id))
                else:
                    self.logger.debug(
                        "\tUnknown Trigger Type %s (%d), %s" % (trigger.name, trigger.id, trigger.pluginTypeId))

                # pattern matching here

    ####################
    def validatePrefsConfigUi(self, valuesDict):
        self.logger.debug(u"validatePrefsConfigUi called")
        errorsDict = indigo.Dict()
        updateFrequency = valuesDict['updateFrequency']
        if len(updateFrequency) == 0 or int(updateFrequency) < 0 or int(updateFrequency) > 168:
            errorsDict['updateFrequency'] = u"Update frequency is invalid - enter number of hours between 0 and 168"

        if len(errorsDict) > 0:
            return (False, valuesDict, errorsDict)
        return (True, valuesDict)

    ########################################
    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            try:
                self.logLevel = int(valuesDict[u"logLevel"])
            except:
                self.logLevel = logging.INFO
            self.indigo_log_handler.setLevel(self.logLevel)
            self.logger.debug(u"logLevel = " + str(self.logLevel))

            self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "24")) * 60.0 * 60.0
            self.logger.debug(u"updateFrequency = " + str(self.updateFrequency))
            self.next_update_check = time.time()

    ########################################
    # Called for each enabled Device belonging to plugin
    # Verify connectivity to servers and start polling IMAP/POP servers here
    #
    def deviceStartComm(self, device):

        instanceVers = int(device.pluginProps.get('devVersCount', 0))
        self.logger.debug(device.name + u": Device Current Version = " + str(instanceVers))

        if instanceVers >= kCurDevVersCount:
            self.logger.debug(device.name + u": Device Version is up to date")

        elif instanceVers < kCurDevVersCount:
            newProps = device.pluginProps

            encryptionType = device.pluginProps.get('encryptionType', "unknown")
            if encryptionType == "unknown":
                useSSL = device.pluginProps.get('useSSL', "false")
                if useSSL:
                    newProps["encryptionType"] = "SSL"
                else:
                    newProps["encryptionType"] = "None"
                self.logger.debug(device.name + u": created encryptionType property")

            if device.deviceTypeId == "imapAccount":
                useIDLE = device.pluginProps.get('useIDLE', "unknown")
                if useIDLE == "unknown":
                    newProps["useIDLE"] = "True"
                    self.logger.debug(device.name + u": created useIDLE property")

            pollingFrequency = device.pluginProps.get('pollingFrequency', "unknown")
            if pollingFrequency == "unknown":
                newProps["pollingFrequency"] = device.pluginProps.get('pollingFrequency', 15)
                self.logger.debug(device.name + u": created pollingFrequency property")

            newProps["devVersCount"] = kCurDevVersCount
            device.replacePluginPropsOnServer(newProps)
            self.logger.debug(u"Updated " + device.name + " to version " + str(kCurDevVersCount))

        else:
            self.logger.error(u"Unknown device version: " + str(instanceVers) + " for device " + device.name)

        if len(device.pluginProps) < 3:
            self.logger.error(u"Server \"%s\" is misconfigured - disabling" % device.name)
            indigo.device.enable(device, value=False)

        else:
            if device.id not in self.serverDict:
                self.logger.debug(u"Starting server: " + device.name)
                if device.deviceTypeId == "imapAccount":
                    self.serverDict[device.id] = self.IMAPServer(device)
                elif device.deviceTypeId == "popAccount":
                    self.serverDict[device.id] = self.POPServer(device)
                elif device.deviceTypeId == "smtpAccount":
                    self.serverDict[device.id] = self.SMTPServer(device)
                else:
                    self.logger.error(u"Unknown server device type: " + str(device.deviceTypeId))
            else:
                self.logger.debug(u"Duplicate Device ID: " + device.name)

    ########################################
    # Terminate communication with servers
    #
    def deviceStopComm(self, device):
        props = device.pluginProps

        if device.id in self.serverDict:
            self.logger.debug(u"Stopping server: " + device.name)
            del self.serverDict[device.id]
        else:
            self.logger.debug(u"Unknown Device ID: " + device.name)

    ########################################

    def runConcurrentThread(self):

        try:
            while True:

                if (self.updateFrequency > 0.0) and (time.time() > self.next_update_check):
                    self.next_update_check = time.time() + self.updateFrequency
                    self.updater.checkForUpdate()

                for serverId, server in self.serverDict.items():
                    if server.pollCheck():
                        server.poll()

                # wait a minute and do it all again.
                self.sleep(60)

        except self.StopThread:
            pass

    ########################################
    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.logger.debug(u"validateDeviceConfigUi called")
        errorsDict = indigo.Dict()

        try:
            name = valuesDict['address']
            if len(name) < 1:
                raise
        except:
            errorsDict['address'] = u"Enter name of server"

        try:
            hostPort = valuesDict['hostPort']
            if len(hostPort) < 1:
                raise
        except:
            errorsDict['hostPort'] = u"Enter server port"

        try:
            poll = int(valuesDict['pollingFrequency'])
            if (poll < 0) or (poll > 1440):
                raise
        except:
            errorsDict['pollingFrequency'] = u"Polling frequency is invalid - enter a valid number (between 0 and 1440)"

        if len(errorsDict) > 0:
            return (False, valuesDict, errorsDict)
        return (True, valuesDict)

    ########################################
    def validateActionConfigUi(self, valuesDict, typeId, devId):
        errorsDict = indigo.Dict()

        if len(errorsDict) > 0:
            return (False, valuesDict, errorsDict)
        return (True, valuesDict)

    ########################################
    # Plugin Actions object callbacks (pluginAction is an Indigo plugin action instance)
    ######################
    def sendEmailAction(self, pluginAction, smtpDevice):
        self.logger.debug(u"sendEmailAction queueing message '" + indigo.activePlugin.substitute(pluginAction.props["emailSubject"]) + "'")
        smtpServer = self.serverDict[smtpDevice.id]
        smtpServer.smtpQ.put(pluginAction)
        smtpServer.poll()

    ########################################
    def clearAllSMTPQueues(self):
        self.logger.debug(u"Clearing all SMTP Queues")
        for serverId, server in self.serverDict.items():
            if server.device.deviceTypeId == "smtpAccount":
                server.smtpQ = Queue()  # just nuke the old queue and replace it

    def clearSMTPQueue(self, device):
        self.logger.debug(u"Clearing SMTP Queue for " + self.serverDict[device.deviceId].device.name)
        self.serverDict[device.deviceId].smtpQ = Queue()  # just nuke the old queue and replace it

    ########################################
    def pollAllServers(self):
        self.logger.debug(u"Polling All Email Servers")
        for serverId, server in self.serverDict.items():
            self.logger.debug(u"Polling serverId: " + str(
                serverId) + ", serverTypeId: " + server.device.deviceTypeId + "(" + server.device.name + ")")
            server.poll()

    def pollServer(self, device):
        self.logger.debug(u"Polling Server: " + self.serverDict[device.deviceId].device.name)
        self.serverDict[device.deviceId].poll()

    ########################################
    # Menu Methods
    ########################################

    def checkForUpdates(self):
        self.updater.checkForUpdate()

    def updatePlugin(self):
        self.updater.update()

    def forceUpdate(self):
        self.updater.update(currentVersion='0.0.0')

    def toggleDebugging(self):
        if self.debug:
            self.logger.debug(u"Turning off debug logging")
            self.pluginPrefs["showDebugInfo"] = False
        else:
            self.logger.debug(u"Turning on debug logging")
            self.pluginPrefs["showDebugInfo"] = True
        self.debug = not self.debug

    def clearSMTPQueueMenu(self, valuesDict, typeId):
        deviceId = int(valuesDict["targetDevice"])
        for serverId, server in self.serverDict.items():
            if serverId == deviceId:
                self.logger.debug(u"Clearing SMTP Queue for " + server.device.name)
                server.smtpQ = Queue()  # just nuke the old queue and replace it
        return True

    def pickSMTPServer(self, filter=None, valuesDict=None, typeId=0):
        retList = []
        for dev in indigo.devices.iter():
            if (dev.pluginId.lower().find("betteremail") > -1) and (dev.deviceTypeId == "smtpAccount"):
                retList.append((dev.id, dev.name))
        retList.sort(key=lambda tup: tup[1])
        return retList

    def pickInboundServer(self, filter=None, valuesDict=None, typeId=0, targetId=0):
        retList = []
        for dev in indigo.devices.iter():
            if (dev.pluginId.lower().find("betteremail") > -1) and (
                        (dev.deviceTypeId == "imapAccount") or (dev.deviceTypeId == "popAccount")):
                retList.append((dev.id, dev.name))
        retList.sort(key=lambda tup: tup[1])
        return retList
