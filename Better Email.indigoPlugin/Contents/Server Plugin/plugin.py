#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import re
import ssl
import smtplib
import poplib
import imaplib2

from email.Parser import Parser, FeedParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Charset
from email.header import Header, decode_header

from Queue import Queue
from threading import Thread, Event

from ghpu import GitHubPluginUpdater

kCurDevVersCount = 3		# current version of plugin devices

################################################################################
class Plugin(indigo.PluginBase):

	########################################
	# Email Server Classes and Methods
	########################################

	# IMAP specific class and methods
	class IMAPServer(object):
				
		def __init__(self, device):
			self.device = device
			self.imapProps = self.device.pluginProps			
			if self.imapProps['useIDLE']:
				self.connect()
				self.thread = Thread(target=self.idle)
				self.event = Event()
				self.thread.start()
			self.pollCounter = 0			# check on first pass			
			
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
					indigo.activePlugin.debugLog(self.device.name + u": Doing connect using encryptionType = " + self.imapProps['encryptionType'])					
					self.connection = imaplib2.IMAP4_SSL(self.imapProps['address'].encode('ascii','ignore'), int(self.imapProps['hostPort']))
					self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
					self.connection.select("INBOX")
			
				elif self.imapProps['encryptionType'] == 'StartTLS':
					indigo.activePlugin.debugLog(self.device.name + u": Doing connect using encryptionType = " + self.imapProps['encryptionType'])					
					self.connection = imaplib2.IMAP4(self.imapProps['address'].encode('ascii','ignore'), int(self.imapProps['hostPort']))
					indigo.activePlugin.debugLog(self.device.name + u": Doing starttls()")					
					self.connection.starttls()
					indigo.activePlugin.debugLog(self.device.name + u": Doing login()")					
					self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
					indigo.activePlugin.debugLog(self.device.name + u": Doing select(\"INBOX\")")					
					self.connection.select("INBOX")	
				
				elif self.imapProps['encryptionType'] == 'None':
					indigo.activePlugin.debugLog(self.device.name + u": Doing connect using encryptionType = " + self.imapProps['encryptionType'])					
					self.connection = imaplib2.IMAP4(self.imapProps['address'].encode('ascii','ignore'), int(self.imapProps['hostPort']))
					self.connection.login(self.imapProps['serverLogin'], self.imapProps['serverPassword'])
					self.connection.select("INBOX")
							
				else:
					indigo.activePlugin.errorLog(u"Unknown encryption type: " + self.imapProps['encryptionType'])

			except Exception, e:
				indigo.activePlugin.debugLog(self.device.name + ': Error connecting to IMAP server: ' + str(e))
				raise
			

		def idle(self):
			indigo.activePlugin.debugLog(self.device.name + u": idle() called")					

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
					indigo.activePlugin.debugLog(self.device.name + u": IDLE Event Received")					
					self.checkMsgs()
					

		def checkMsgs(self):
			indigo.activePlugin.debugLog(self.device.name + u": Doing checkMsgs")					
			typ, msg_ids = self.connection.search(None, 'ALL')
			indigo.activePlugin.debugLog(self.device.name + u": msg_ids = " + str(msg_ids))					
			for messageNum in msg_ids[0].split():
				indigo.activePlugin.debugLog(self.device.name + u": Checking Message # " + messageNum)					
				try:
					typ, resp = self.connection.fetch(messageNum, '(FLAGS)')
					if "$IndigoProcessed" in resp[0]:
						indigo.activePlugin.debugLog(self.device.name + u": Message # " + messageNum + " already seen, skipping...")
						continue
				except Exception, e:
					indigo.activePlugin.debugLog(self.device.name + ': Error fetching FLAGS for Message # ' + messageNum + ": " + str(e))
					pass
				try:
					indigo.activePlugin.debugLog(self.device.name + u": Fetching Message # " + messageNum)
					typ, data = self.connection.fetch(messageNum, '(RFC822)')
					parser = Parser()
					message = parser.parsestr(data[0][1])
					
					bytes, encoding = decode_header(message.get("Subject"))[0]
					if encoding:
						messageSubject = bytes.decode(encoding)
					else:
						messageSubject = message.get("Subject")
					self.device.updateStateOnServer(key="messageSubject", value=messageSubject)					
					indigo.activePlugin.debugLog(u"Received Message Subject: " + messageSubject)
					
					bytes, encoding = decode_header(message.get("From"))[0]
					if encoding:
						messageFrom = bytes.decode(encoding)
					else:
						messageFrom = message.get("From")
					self.device.updateStateOnServer(key="messageFrom", value=messageFrom)					
					indigo.activePlugin.debugLog(u"Received Message From: " + messageFrom)

					messageID = message.get("Message-Id")
					self.device.updateStateOnServer(key="lastMessage", value=messageID)
				
					if message.is_multipart():
						part0 = message.get_payload(0)		# we only look at the first alternative content part
						messageText = part0.get_payload(decode=True).decode(part0.get_content_charset())
					else:
						messageText = message.get_payload(decode=True).decode(message.get_content_charset())
					self.device.updateStateOnServer(key="messageText", value=messageText)
					indigo.activePlugin.debugLog(u"Received Message Text: " + messageText)
				
					indigo.activePlugin.triggerCheck(self.device)
					
					# If configured to do so, delete the message, otherwise mark it as processed
					if self.imapProps['delete']:
						indigo.activePlugin.debugLog(u"Deleting message # " + messageNum)
						t, resp = self.connection.store(messageNum, '+FLAGS', r'(\Deleted)')
					else:
						# Mark the message as successfully processed
						t, resp = self.connection.store(messageNum, '+FLAGS', r'($IndigoProcessed)')
				except Exception, e:
					indigo.activePlugin.debugLog('Error fetching Message # ' + messageNum + ": " + str(e))
			self.connection.expunge()
		
				
		def pollCheck(self):
			if self.device.pluginProps['useIDLE']:		# skip poll when using IDLE
				return False
			
			counter = int(self.device.pluginProps['pollingFrequency'])
			if counter == 0:		# no polling for frequency = 0
				return False
				
			self.pollCounter -= 1
			if self.pollCounter <= 0:
				self.pollCounter = counter
				return True
			else: 
				return False
		
		
		def poll(self):
			if self.imapProps['useIDLE']:		# skip poll when using IDLE
				indigo.activePlugin.debugLog(u"Skipping IMAP Server using IDLE: " + self.device.name)
				return
				
			indigo.activePlugin.debugLog(u"Polling IMAP Server: " + self.device.name)
			
			try:
				self.connect()
				self.checkMsgs()
				
				# close the connection and log out
				self.device.updateStateOnServer(key="serverStatus", value="Success")
				self.connection.close()
				self.connection.logout()
				indigo.activePlugin.debugLog(u"Logged out from IMAP server: " + self.device.name)
			except Exception, e:
				indigo.activePlugin.errorLog(u"IMAP server connection error: " + str(e))
				self.device.updateStateOnServer(key="serverStatus", value="Failure")
	
		
	# POP specific class and methods
	class POPServer(object):
	
		def __init__(self, device):
			self.device = device
			self.pollCounter = 0			# check on first pass			

		def __str__(self):
			return self.status

		def pollCheck(self):
			counter = int(self.device.pluginProps['pollingFrequency'])
			if counter == 0:		# no polling for frequency = 0
				return False
				
			self.pollCounter -= 1
			if self.pollCounter <= 0:
				self.pollCounter = counter
				return True
			else: 
				return False
		
		def poll(self):
			indigo.activePlugin.debugLog(u"Connecting to POP Server: " + self.device.name)
			props = self.device.pluginProps		
			oldMessageList = indigo.activePlugin.pluginPrefs.get(u"readMessages",indigo.List())
			newMessageList = indigo.List()

			try:
				if self.props['encryptionType'] == 'SSL':
					connection = poplib.POP3_SSL(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				elif self.props['encryptionType'] == 'None':
					connection = poplib.POP3(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				else:
					indigo.activePlugin.errorLog(u"Unknown encryption type: " + self.imapProps['encryptionType'])
					return
					
				connection.user(props['serverLogin'])
				connection.pass_(props['serverPassword'])				
				(numMessages, totalSize) = connection.stat()				
				if numMessages == 0:
					indigo.activePlugin.debugLog(u"No messages to process")
										
				for i in range(numMessages):
					messageNum = i + 1
					indigo.activePlugin.debugLog(u"Retrieving Message # " + str(messageNum))					
					try:
						(server_msg, body, octets) = connection.retr(messageNum)
						uidl = connection.uidl(messageNum).split()[2]
						newMessageList.append(str(uidl))
						if uidl in oldMessageList:
							indigo.activePlugin.debugLog(u"Message " + uidl + " already seen, skipping...")											
							continue
						
						indigo.activePlugin.debugLog(u"Parsing message " + uidl)
						parser = FeedParser()
						for line in body:
							parser.feed(str(line + '\n'))
						message = parser.close()

						bytes, encoding = decode_header(message.get("Subject"))[0]
						if encoding:
							messageSubject = bytes.decode(encoding)
						else:
							messageSubject = message.get("Subject")
						self.device.updateStateOnServer(key="messageSubject", value=messageSubject)
						indigo.activePlugin.debugLog(u"Received Message Subject: " + messageSubject)

						bytes, encoding = decode_header(message.get("From"))[0]
						if encoding:
							messageFrom = bytes.decode(encoding)
						else:
							messageFrom = message.get("From")
						self.device.updateStateOnServer(key="messageFrom", value=messageFrom)					
						indigo.activePlugin.debugLog(u"Received Message From: " + messageFrom)

						if message.is_multipart():
							messageText = message.get_payload(0).get_payload(decode=True).decode(message.get_content_charset())
						else:
							messageText = message.get_payload(decode=True).decode(message.get_content_charset())
						self.device.updateStateOnServer(key="messageText", value=messageText)					
						indigo.activePlugin.debugLog(u"Received Message Text: " + messageText)

						self.device.updateStateOnServer(key="lastMessage", value=uidl)
					
						indigo.activePlugin.triggerCheck(self.device)

						# If configured to do so, delete the message, otherwise mark it as processed
						if props['delete']:
							indigo.activePlugin.debugLog(u"Deleting Message # " + str(messageNum))
							connection.dele(messageNum)

					except Exception, e:
						indigo.activePlugin.debugLog('Error fetching Message ' + str(messageNum) + ": " + str(e))
						pass
					
				# close the connection and log out
				indigo.activePlugin.pluginPrefs[u"readMessages"] = newMessageList
				self.device.updateStateOnServer(key="serverStatus", value="Success")
				connection.quit()
				indigo.activePlugin.debugLog(u"Logged out from POP server")
				
			except Exception, e:
				indigo.activePlugin.errorLog(u"POP server connection error: " + str(e))
				self.device.updateStateOnServer(key="serverStatus", value="Failure")	
		
	# SMTP specific class and methods
	class SMTPServer(object):
	
		def __init__(self, device):
			self.device = device
			self.smtpQ = Queue()
			self.pollCounter = 0			# check on first pass			

		def __str__(self):
			return self.status

		def smtpSend(self, pluginAction):

			def nonascii(str):
				return not all(ord(c) < 128 for c in str)	

			def addheader(message, headername, headervalue):
				if len(headervalue) == 0:
					return message 
				if nonascii(headervalue):
					h = Header(headervalue, 'utf-8')
					message[headername] = h
				else:
					message[headername] = headervalue	 
				return message

			indigo.activePlugin.debugLog(u"Sending to SMTP Server: " + self.device.name)
	
			smtpDevice = indigo.devices[pluginAction.deviceId]
			smtpProps = smtpDevice.pluginProps

			if "emailTo" in pluginAction.props:
				emailTo =  indigo.activePlugin.substitute(pluginAction.props["emailTo"])
			else:
				indigo.activePlugin.errorLog(u"No emailTo property in plugin property dict")
				return
			
			if "emailSubject" in pluginAction.props:
				emailSubject =	indigo.activePlugin.substitute(pluginAction.props["emailSubject"])
			else:
				indigo.activePlugin.errorLog(u"No emailSubject property in plugin property dict")
				return
			
			if "emailMessage" in pluginAction.props:
				emailMessage =	indigo.activePlugin.substitute(pluginAction.props["emailMessage"])
			else:
				indigo.activePlugin.errorLog(u"No emailMessage property in plugin property dict")
				return

			emailCC = indigo.activePlugin.substitute(pluginAction.props.get("emailCC", ""))
			emailBCC = indigo.activePlugin.substitute(pluginAction.props.get("emailBCC", ""))

			# Override python's weird assumption that utf-8 text should be encoded with
			# base64, and instead use quoted-printable. 
			Charset.add_charset('utf-8', Charset.QP, Charset.QP, 'utf-8')
			
			if (nonascii(emailMessage)):
				msg = MIMEText(emailMessage,'plain','utf-8') 
			else:
				msg = MIMEText(emailMessage,'plain')

			msg = addheader(msg, 'From', smtpProps["fromAddress"])
			msg = addheader(msg, 'Subject', emailSubject)
			msg = addheader(msg, 'To', emailTo)
			msg = addheader(msg, 'Cc', emailCC)
			msg = addheader(msg, 'Bcc', emailBCC)
						
			toAddresses = emailTo.split(",") + emailCC.split(",") + emailBCC.split(",")

			try:
				if smtpProps['encryptionType'] == 'SSL':
					connection = smtplib.SMTP_SSL(smtpProps['address'].encode('ascii','ignore'), int(smtpProps['hostPort']))
					connection.ehlo()
					connection.login(smtpProps["serverLogin"],smtpProps["serverPassword"])
					connection.sendmail(smtpProps["fromAddress"], toAddresses, msg.as_string())
					connection.quit()
					smtpDevice.updateStateOnServer(key="serverStatus", value="Success")
					return True

				elif smtpProps['encryptionType'] == 'StartTLS':
					connection = smtplib.SMTP(smtpProps['address'].encode('ascii','ignore'), int(smtpProps['hostPort']))
					connection.ehlo()
					connection.starttls()
					connection.ehlo()
					connection.login(smtpProps["serverLogin"],smtpProps["serverPassword"])
					connection.sendmail(smtpProps["fromAddress"], toAddresses, msg.as_string())
					connection.quit()
					smtpDevice.updateStateOnServer(key="serverStatus", value="Success")
					return True

				elif smtpProps['encryptionType'] == 'None':
					connection = smtplib.SMTP(smtpProps['address'].encode('ascii','ignore'), int(smtpProps['hostPort']))
					connection.ehlo()
					connection.login(smtpProps["serverLogin"],smtpProps["serverPassword"])
					connection.sendmail(smtpProps["fromAddress"], toAddresses, msg.as_string())
					connection.quit()
					smtpDevice.updateStateOnServer(key="serverStatus", value="Success")
					return True

				else:
					indigo.activePlugin.errorLog(u"Unknown encryption type: " + smtpProps['encryptionType'])
					return False	
				
			except Exception, e:
				indigo.activePlugin.errorLog(self.device.name + u": SMTP server connection error: " + str(e))
				smtpDevice.updateStateOnServer(key="serverStatus", value="Failure")
				return False	

		def pollCheck(self):
			counter = int(self.device.pluginProps['pollingFrequency'])
			if counter == 0:		# no polling for frequency = 0
				return False
				
			self.pollCounter -= 1
			if self.pollCounter <= 0:
				self.pollCounter = counter
				return True
			else: 
				return False
		
		def poll(self):
			indigo.activePlugin.debugLog(self.device.name + u": SMTP poll, " + str(self.smtpQ.qsize()) + u" items in queue")
			while not self.smtpQ.empty():
				action = self.smtpQ.get(False)
				if not self.smtpSend(action):
					self.smtpQ.put(action)		# put back in queue if sending fails
					return
					
	########################################
	# Main Plugin methods
	########################################
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = pluginPrefs.get(u"showDebugInfo", False)

		self.updater = GitHubPluginUpdater(self)

		self.serverDict = dict()		# IMAP/POP servers to poll
		self.triggers = { }

	def __del__(self):
		indigo.PluginBase.__del__(self)

	####################

	def getDeviceConfigUiValues(self, pluginProps, typeId, devId):
		self.debugLog("getDeviceConfigUiValues, typeID = " + typeId)
		valuesDict = indigo.Dict(pluginProps)
		errorsDict = indigo.Dict()

		if len(valuesDict) == 0:
			self.debugLog("getDeviceConfigUiValues: no values, populating encryptionType and hostPort")
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
			self.debugLog("getDeviceConfigUiValues: no change, already populated")

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
		self.debugLog("Adding Trigger %s (%d)" % (trigger.name, trigger.id))
		assert trigger.id not in self.triggers
		self.triggers[trigger.id] = trigger
 
	def triggerStopProcessing(self, trigger):
		self.debugLog("Removing Trigger %s (%d)" % (trigger.name, trigger.id))
		assert trigger.id in self.triggers
		del self.triggers[trigger.id] 

	def triggerCheck(self, device):
		self.debugLog("Checking Triggers for Device %s (%d)" % (device.name, device.id))
	
		for triggerId, trigger in sorted(self.triggers.iteritems()):
			self.debugLog("\tChecking Trigger %s (%d)" % (trigger.name, trigger.id))
			
			# pattern matching here		
			
			field = trigger.pluginProps["fieldPopUp"]
			pattern = trigger.pluginProps["regexPattern"]
			self.debugLog("\tChecking Device State %s for Pattern: %s" % (field, pattern))
	
			cPattern = re.compile(pattern)
			match = cPattern.search(device.states[field])
			if match:
				regexMatch = match.group()
				self.debugLog("\tExecuting Trigger %s (%d), match: %s" % (trigger.name, trigger.id, regexMatch))
				device.updateStateOnServer(key="regexMatch", value=regexMatch)
				indigo.trigger.execute(trigger)
			else:
				self.debugLog("\tNo Match for Trigger %s (%d)" % (trigger.name, trigger.id))
			
	
	####################
	def validatePrefsConfigUi(self, valuesDict):
		self.debugLog(u"validatePrefsConfigUi called")
		errorMsgDict = indigo.Dict()
		try:
			poll = int(valuesDict['pollingFrequency'])
			if (poll < 0) or (poll > 1440):
				raise
		except:
			errorMsgDict['pollingFrequency'] = u"Polling frequency is invalid - enter a valid number (between 0 and 1440)"
		if len(errorMsgDict) > 0:
			return (False, valuesDict, errorMsgDict)
		return (True, valuesDict)

	########################################
	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		if not userCancelled:
			self.debug = valuesDict.get("showDebugInfo", False)
			if self.debug:
				self.debugLog(u"Debug logging enabled")
			else:
				self.debugLog(u"Debug logging disabled")

	########################################
	# Called for each enabled Device belonging to plugin
	# Verify connectivity to servers and start polling IMAP/POP servers here
	#
	def deviceStartComm(self, device):
				
		instanceVers = int(device.pluginProps.get('devVersCount', 0))
		self.debugLog(device.name + u": Device Current Version = " + str(instanceVers))

		if instanceVers >= kCurDevVersCount:
			self.debugLog(device.name + u": Device Version is up to date")
			
		elif instanceVers < kCurDevVersCount:
			newProps = device.pluginProps

			encryptionType = device.pluginProps.get('encryptionType', "unknown")
			if encryptionType == "unknown":
				useSSL = device.pluginProps.get('useSSL', "false")
				if useSSL:
					newProps["encryptionType"] = "SSL"
				else:
					newProps["encryptionType"] = "None"
				self.debugLog(device.name + u": created encryptionType property")
				
			if device.deviceTypeId == "imapAccount":
				useIDLE = device.pluginProps.get('useIDLE', "unknown")	
				if useIDLE == "unknown":
					newProps["useIDLE"] = "True"		
					self.debugLog(device.name + u": created useIDLE property")
				
			pollingFrequency = device.pluginProps.get('pollingFrequency', "unknown")
			if pollingFrequency == "unknown":
				newProps["pollingFrequency"] = self.pluginProps.get('pollingFrequency', 15)
				self.debugLog(device.name + u": created pollingFrequency property")
		
			newProps["devVersCount"] = kCurDevVersCount
			device.replacePluginPropsOnServer(newProps)
			self.debugLog(u"Updated " + device.name + " to version " + str(kCurDevVersCount))

		else:
			self.errorLog(u"Unknown device version: " + str(instanceVers) + " for device " + device.name)					
			
		if len(device.pluginProps) < 3:
			self.errorLog(u"Server \"%s\" is misconfigured - disabling" % device.name)
			indigo.device.enable(device, value=False)
	
		else:			
			if device.id not in self.serverDict:
				self.debugLog(u"Starting server: " + device.name)
				if device.deviceTypeId == "imapAccount":
					self.serverDict[device.id] = self.IMAPServer(device)			
				elif device.deviceTypeId == "popAccount":
					self.serverDict[device.id] = self.POPServer(device)
				elif device.deviceTypeId == "smtpAccount":
					self.serverDict[device.id] = self.SMTPServer(device)
				else:
					self.errorLog(u"Unknown server device type: " + str(device.deviceTypeId))					
			else:
				self.debugLog(u"Duplicate Device ID: " + device.name)
			
			
	########################################
	# Terminate communication with servers
	#
	def deviceStopComm(self, device):
		props = device.pluginProps

		if device.id in self.serverDict:
			self.debugLog(u"Stopping server: " + device.name)
			del self.serverDict[device.id]
		else:
			self.debugLog(u"Unknown Device ID: " + device.name)
			

	########################################
	# If runConcurrentThread() is defined, then a new thread is automatically created
	# and runConcurrentThread() is called in that thread after startup() has been called.
	#
	# runConcurrentThread() should loop forever and only return after self.stopThread
	# becomes True. If this function returns prematurely then the plugin host process
	# will log an error and attempt to call runConcurrentThread() again after several seconds.
	def runConcurrentThread(self):
	
		updateCount = 0  
		
		try:
			while True:
			
				# do update check first
				updateCount -= 1
				if updateCount <= 0:
					self.updater.checkForUpdate()
					updateCount = int(self.pluginPrefs['updateFrequency'] * 60) # convert hours to minutes
					
				# now see if any email server devices need to poll
				
				for serverId, server in self.serverDict.items():
					if server.pollCheck():
						server.poll()
					
				# wait a minute and do it all again.
				self.sleep(60)
				
		except self.StopThread:
			pass
 
	########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		errorsDict = indigo.Dict()
		if len(errorsDict) > 0:
			return (False, valuesDict, errorsDict)
		return (True, valuesDict)

	########################################
	def validateActionConfigUi(self, valuesDict, typeId, devId):
		errorsDict = indigo.Dict()
		try:
			pass
		except:
			pass
		if len(errorsDict) > 0:
			return (False, valuesDict, errorsDict)
		return (True, valuesDict)

	########################################
	# Plugin Actions object callbacks (pluginAction is an Indigo plugin action instance)
	######################
	def sendEmailAction(self, pluginAction):
		self.debugLog(u"sendEmailAction queueing message '" + indigo.activePlugin.substitute(pluginAction.props["emailSubject"]) + "'")
		smtpDevice = indigo.devices[pluginAction.deviceId]
		smtpServer = self.serverDict[smtpDevice.id]
		smtpServer.smtpQ.put(pluginAction)
		smtpServer.poll()

	########################################
	def clearAllSMTPQueues(self):
		self.debugLog(u"Clearing all SMTP Queues")
		for serverId, server in self.serverDict.items():
			if server.device.deviceTypeId == "smtpAccount":
				server.smtpQ = Queue()			# just nuke the old queue and replace it

	def clearSMTPQueue(self, device):
		self.debugLog(u"Clearing SMTP Queue for " + self.serverDict[device.deviceId].device.name)
		self.serverDict[device.deviceId].smtpQ = Queue()			# just nuke the old queue and replace it
   
	########################################
	def pollAllServers(self):
		self.debugLog(u"Polling All Email Servers")
		for serverId, server in self.serverDict.items():
			self.debugLog(u"Polling serverId: " + str(serverId) + ", serverTypeId: " + server.device.deviceTypeId + "(" + server.device.name + ")")
			server.poll()

	def pollServer(self, device):
		self.debugLog(u"Polling Server: " + self.serverDict[device.deviceId].device.name)
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
			self.debugLog(u"Turning off debug logging")
			self.pluginPrefs["showDebugInfo"] = False
		else:
			self.debugLog(u"Turning on debug logging")
			self.pluginPrefs["showDebugInfo"] = True
		self.debug = not self.debug

	def clearSMTPQueueMenu(self, valuesDict, typeId):		
		deviceId=int(valuesDict["targetDevice"])
		for serverId, server in self.serverDict.items():
			if serverId == deviceId:
				self.debugLog(u"Clearing SMTP Queue for " + server.device.name)
				server.smtpQ = Queue()			# just nuke the old queue and replace it
		return True			
		 
	def pickSMTPServer(self, filter=None, valuesDict=None, typeId=0):
		retList =[]
		for dev in indigo.devices.iter():
			if (dev.pluginId.lower().find("betteremail") > -1) and (dev.deviceTypeId == "smtpAccount"): 
				retList.append(dev.id,dev.name)
		return retList
