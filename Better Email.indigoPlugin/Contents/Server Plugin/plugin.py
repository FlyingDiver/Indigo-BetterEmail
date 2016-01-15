#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015-2016, Joe Keenan, joe@flyingdiver.com

import indigo

import re
import smtplib
import poplib

from email.Parser import Parser, FeedParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Charset
from email.header import Header

from Queue import Queue

from threading import Thread, Event

import indigoPluginUpdateChecker
import imaplib2

################################################################################
class Plugin(indigo.PluginBase):

	########################################
	# Email Server Classes and Methods
	########################################

	# IMAP specific class and methods
	class IMAPServer(object):
				
		def __init__(self, device):
			self.device = device
			props = self.device.pluginProps			
			if props['useIDLE']:
				if props['useSSL']:
					self.connection = imaplib2.IMAP4_SSL(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				else:
					self.connection = imaplib2.IMAP4(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				self.connection.login(props['serverLogin'], props['serverPassword'])
				self.connection.select("INBOX")
				self.checkMsgs()							# on startup, just in case some are waiting
        		self.thread = Thread(target=self.idle)
        		self.event = Event()

		def __str__(self):
			return self.status

		def start(self):
			self.thread.start()
 
		def stop(self):
			self.event.set()
 
		def close(self):
			self.connection.close()
			self.connection.logout()
 
		def idle(self):

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
			props = self.device.pluginProps			
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
					if message.is_multipart():
						messageText = message.get_payload(0).get_payload()
					else:
						messageText = message.get_payload()
					
					messageSubject = message.get("Subject")
					messageFrom = message.get("From")
					messageID = message.get("Message-Id")
				
					self.device.updateStateOnServer(key="messageText", value=messageText)
					self.device.updateStateOnServer(key="messageSubject", value=messageSubject)					
					self.device.updateStateOnServer(key="messageFrom", value=messageFrom)					
					self.device.updateStateOnServer(key="lastMessage", value=messageID)
				
					indigo.activePlugin.triggerCheck(self.device)
					
					# If configured to do so, delete the message, otherwise mark it as processed
					if props['delete']:
						indigo.activePlugin.debugLog(u"Deleting message # " + messageNum)
						t, resp = self.connection.store(messageNum, '+FLAGS', r'(\Deleted)')
					else:
						# Mark the message as successfully processed
						t, resp = self.connection.store(messageNum, '+FLAGS', r'($IndigoProcessed)')
				except Exception, e:
					indigo.activePlugin.debugLog('Error fetching Message # ' + messageNum + ": " + str(e))
			self.connection.expunge()
				
		def poll(self):
			props = self.device.pluginProps			
			if props['useIDLE']:		# skip poll when using IDLE
				indigo.activePlugin.debugLog(u"Skipping IMAP Server using IDLE: " + self.device.name)
				return
				
			indigo.activePlugin.debugLog(u"Connecting to IMAP Server: " + self.device.name)
			
			try:
				if props['useSSL']:
					self.connection = imaplib2.IMAP4_SSL(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				else:
					self.connection = imaplib2.IMAP4(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				self.connection.login(props['serverLogin'], props['serverPassword'])
				self.connection.select("INBOX")
				
				self.checkMsgs()
				
				# close the connection and log out
				self.device.updateStateOnServer(key="serverStatus", value="Success")
				self.connection.close()
				self.connection.logout()
				indigo.activePlugin.debugLog(u"Logged out from IMAP server")
			except Exception, e:
				indigo.activePlugin.errorLog(u"IMAP server connection error: " + str(e))
				self.device.updateStateOnServer(key="serverStatus", value="Failure")
	
		
	# POP specific class and methods
	class POPServer(object):
	
		def __init__(self, device):
			self.device = device

		def __str__(self):
			return self.status

		def poll(self):
			indigo.activePlugin.debugLog(u"Connecting to POP Server: " + self.device.name)
			props = self.device.pluginProps		
			oldMessageList = indigo.activePlugin.pluginPrefs.get(u"readMessages",indigo.List())
			newMessageList = indigo.List()

			try:
				if props['useSSL']:
					connection = poplib.POP3_SSL(props['address'].encode('ascii','ignore'), int(props['hostPort']))
				else:
					connection = poplib.POP3(props['address'].encode('ascii','ignore'), int(props['hostPort']))
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

						messageSubject = message.get("Subject")
						messageFrom = message.get("From")
						indigo.activePlugin.debugLog(u"Message Subject: " + messageSubject)

						if message.is_multipart():
							messageText = message.get_payload(0).get_payload()
						else:
							messageText = message.get_payload()
						indigo.activePlugin.debugLog(u"Message Text: " + messageText)

						self.device.updateStateOnServer(key="messageSubject", value=messageSubject)
						self.device.updateStateOnServer(key="messageText", value=messageText)					
						self.device.updateStateOnServer(key="messageFrom", value=messageFrom)					
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
				emailSubject =  indigo.activePlugin.substitute(pluginAction.props["emailSubject"])
			else:
				indigo.activePlugin.errorLog(u"No emailSubject property in plugin property dict")
				return
			
			if "emailMessage" in pluginAction.props:
				emailMessage =  indigo.activePlugin.substitute(pluginAction.props["emailMessage"])
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
				if smtpProps['useSSL']:
					connection = smtplib.SMTP_SSL(smtpProps['address'].encode('ascii','ignore'), int(smtpProps['hostPort']))
				else:
					connection = smtplib.SMTP(smtpProps['address'].encode('ascii','ignore'), int(smtpProps['hostPort']))
	
				connection.login(smtpProps["serverLogin"],smtpProps["serverPassword"])
				connection.sendmail(smtpProps["fromAddress"], toAddresses, msg.as_string())
				connection.quit()
				smtpDevice.updateStateOnServer(key="serverStatus", value="Success")
				return True

			except Exception, e:
				indigo.activePlugin.errorLog(u"SMTP server connection error: " + str(e))
				smtpDevice.updateStateOnServer(key="serverStatus", value="Failure")
				return False	

		def poll(self):
			indigo.activePlugin.debugLog(u"SMTP poll, " + str(self.smtpQ.qsize()) + " items in queue")
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
	
		self.updater = indigoPluginUpdateChecker.updateChecker(self, "https://dl.dropboxusercontent.com/u/7563539/BEVersionInfo.html", 1)
		
		self.serverDict = dict()		# IMAP/POP servers to poll
		self.triggers = { }

	def __del__(self):
		indigo.PluginBase.__del__(self)

	def startup(self):
		self.debugLog(u"startup called")
		try: 
			self.updater.checkVersionPoll()
		except:
			self.errorLog(u"Update checker error.")
			
	def shutdown(self):
		self.debugLog(u"shutdown called")

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
		props = device.pluginProps

#		kCurDevVersCount = 1		# current version of plugin devices
#				
#		instanceVers = int(props.get('devVersCount', 0))
#		if instanceVers >= kCurDevVersCount:
#			continue   # optimization: bail out since dev is already up-to-date
#			
#		elif instanceVers < 1:
#			# make changes to device to get it up to version 1, including calling stateListOrDisplayStateIdChanged if needed.
#			props["devVersCount"] = kCurDevVersCount
#			dev.replacePluginPropsOnServer(props)
#			self.debugLog(u"Updated " + device.name + " to version " + str(kCurDevVersCount))
#
#		else:
#			self.errorLog(u"Unknown device version: " + str(instanceVers) + " for device " + device.name)					
    
		# need better error checking here
		
		if len(props) < 3:
			self.errorLog(u"Server \"%s\" is misconfigured - disabling" % device.name)
			indigo.device.enable(device, value=False)
	
		else:			
			if device.id not in self.serverDict:
				self.debugLog(u"Starting server: " + device.name)
				if device.deviceTypeId == "imapAccount":
					self.serverDict[device.id] = self.IMAPServer(device)			
					if props['useIDLE']:
						self.serverDict[device.id].start()
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
			if device.deviceTypeId == "imapAccount":
				self.serverDict[device.id] = self.IMAPServer(device)			
				if props['useIDLE']:
					self.serverDict[device.id].stop()
					self.serverDict[device.id].close()
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
		try:
			while True:
				self.updater.checkVersionPoll()
				interval = int(self.pluginPrefs['pollingFrequency'])
				if interval == 0:
					self.sleep(60)
				else:
					self.pollAllServers()
					self.debugLog(u"Next poll in %s minutes" % str(interval))
					self.sleep(interval * 60)
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
		self.debugLog(u"Polling Email Servers")
		for serverId, server in self.serverDict.items():
			self.debugLog(u"serverId: " + str(serverId) + ", serverTypeId: " + server.device.deviceTypeId)
			server.poll()

	def pollServer(self, device):
		self.debugLog(u"Polling Server: " + self.serverDict[device.deviceId].device.name)
		self.serverDict[device.deviceId].poll()

	########################################
	# Menu Methods
	########################################
	def checkVersionNow(self):
		self.debugLog(u"checkVersionNow() method called.")
		self.updater.checkVersionNow()
		
	def toggleDebugging(self):
		if self.debug:
			self.debugLog(u"Turning off debug logging")
			self.pluginPrefs["showDebugInfo"] = False
		else:
			iself.debugLog(u"Turning on debug logging")
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
