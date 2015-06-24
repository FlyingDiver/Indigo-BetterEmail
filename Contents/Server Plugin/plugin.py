#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2015, Joe Keenan, joe@flyingdiver.com

import indigo

import smtplib
import imaplib
import poplib
from email.Parser import Parser, FeedParser

################################################################################
class Plugin(indigo.PluginBase):

	########################################
	# Email Server Classes and Methods
	########################################

	# IMAP specific class and methods
	class IMAPServer(object):
				
		def __init__(self, device):
			self.device = device

		def __str__(self):
			return self.status

		def poll(self):
			props = self.device.pluginProps			
			indigo.activePlugin.debugLog("Connecting to IMAP Server: " + props["serverName"])
			
			try:
				if props['useSSL']:
					connection = imaplib.IMAP4_SSL(props['hostName'].encode('ascii','ignore'), int(props['hostPort']))
				else:
					connection = imaplib.IMAP4(props['hostName'].encode('ascii','ignore'), int(props['hostPort']))
				connection.login(props['serverLogin'], props['serverPassword'])
				connection.select()
				typ, msg_ids = connection.search(None, 'ALL')
				for messageNum in msg_ids[0].split():
					indigo.activePlugin.debugLog("Retrieving Message # " + messageNum)					
					try:
						typ, resp = connection.fetch(messageNum, '(FLAGS)')
						if "$IndigoProcessed" in resp[0]:
							indigo.activePlugin.debugLog("Message # " + messageNum + " already seen, skipping...")
							continue
					except Exception, e:
						indigo.activePlugin.debugLog('Error fetching FLAGS for Message # ' + messageNum + ": " + str(e))
						pass
					try:
						indigo.activePlugin.debugLog("Fetching message # " + messageNum)
						typ, data = connection.fetch(messageNum, '(RFC822)')
						parser = Parser()
						message = parser.parsestr(data[0][1])
						if message.is_multipart():
							messageText = message.get_payload(0).get_payload()
						else:
							messageText = message.get_payload()
						
						messageSubject = message.get("Subject")
						messageID = message.get("Message-Id")
					
						self.device.updateStateOnServer(key="messageText", value=messageText)
						self.device.updateStateOnServer(key="messageSubject", value=messageSubject)					
						self.device.updateStateOnServer(key="lastMessage", value=messageID)
					
						# If configured to do so, delete the message, otherwise mark it as processed
						if props['delete']:
							t, resp = connection.store(messageNum, '+FLAGS', r'(\Deleted)')
							connection.expunge()
						else:
							# Mark the message as successfully processed
							t, resp = connection.store(messageNum, '+FLAGS', r'($IndigoProcessed)')
					except Exception, e:
						indigo.activePlugin.debugLog('Error fetching Message # ' + messageNum + ": " + str(e))
					
				else:
					indigo.activePlugin.debugLog("No messages to process")
				# close the connection and log out
				self.device.updateStateOnServer(key="serverStatus", value="Success")
				connection.close()
				connection.logout()
				indigo.activePlugin.debugLog("Logged out from IMAP server")
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
			oldMessageList = indigo.activePlugin.pluginPrefs.get(u"readMessages",indigo.List())
			newMessageList = indigo.List()
			props = self.device.pluginProps		
			indigo.activePlugin.debugLog("Connecting to POP Server: " + props["serverName"])

			try:
				if props['useSSL']:
					connection = poplib.POP3_SSL(props['hostName'].encode('ascii','ignore'), int(props['hostPort']))
				else:
					connection = poplib.POP3(props['hostName'].encode('ascii','ignore'), int(props['hostPort']))
				connection.user(props['serverLogin'])
				connection.pass_(props['serverPassword'])				
				(numMessages, totalSize) = connection.stat()				
				if numMessages == 0:
					indigo.activePlugin.debugLog("No messages to process")
										
				for i in range(numMessages):
					messageNum = i + 1
					indigo.activePlugin.debugLog("Retrieving Message # " + str(messageNum))					
					try:
						(server_msg, body, octets) = connection.retr(messageNum)
						uidl = connection.uidl(messageNum).split()[2]
						newMessageList.append(str(uidl))
						if uidl in oldMessageList:
							indigo.activePlugin.debugLog("Message " + uidl + " already seen, skipping...")											
							continue
						
						indigo.activePlugin.debugLog("Parsing message " + uidl)
						parser = FeedParser()
						for line in body:
							parser.feed(str(line + '\n'))
						message = parser.close()

						messageSubject = message.get("Subject")
						indigo.activePlugin.debugLog("Message Subject: " + messageSubject)

						if message.is_multipart():
							messageText = message.get_payload(0).get_payload()
						else:
							messageText = message.get_payload()
						indigo.activePlugin.debugLog("Message Text: " + messageText)

						self.device.updateStateOnServer(key="messageSubject", value=messageSubject)
						self.device.updateStateOnServer(key="messageText", value=messageText)					
						self.device.updateStateOnServer(key="lastMessage", value=uidl)
					
						# If configured to do so, delete the message, otherwise mark it as processed
						if props['delete']:
							connection.dele(messageNum)
							indigo.activePlugin.debugLog("Deleting Message: " + str(messageNum))

					except Exception, e:
						indigo.activePlugin.debugLog('Error fetching Message ' + str(messageNum) + ": " + str(e))
						pass
					
				# close the connection and log out
				indigo.activePlugin.pluginPrefs[u"readMessages"] = newMessageList
				self.device.updateStateOnServer(key="serverStatus", value="Success")
				connection.quit()
				indigo.activePlugin.debugLog("Logged out from POP server")
				
			except Exception, e:
				indigo.activePlugin.errorLog(u"POP server connection error: " + str(e))
				self.device.updateStateOnServer(key="serverStatus", value="Failure")	
		
	# SMTP specific class and methods
	class SMTPServer(object):
	
		def __init__(self, device):
			self.device = device

		def __str__(self):
			return self.status

		def poll(self):
#			Nothing to do right now. 
#			To do:  queue up messages in case of connection failure
#			
#			props = self.device.pluginProps		
#			indigo.activePlugin.debugLog("Sending to SMTP Server: " + props["serverName"])
			pass			


	########################################
	# Main Plugin methods
	########################################
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = pluginPrefs.get("showDebugInfo", False)
		
		self.serverDict = dict()		# IMAP/POP servers to poll

	def __del__(self):
		indigo.PluginBase.__del__(self)

	########################################
	def startup(self):
		self.debugLog(u"startup called")

	def shutdown(self):
		self.debugLog(u"shutdown called")

	
	####################
	def validatePrefsConfigUi(self, valuesDict):
		self.debugLog(u"validatePrefsConfigUi called")
		errorMsgDict = indigo.Dict()
		try:
			poll = int(valuesDict['pollingFrequency'])
			if (poll < 1) or (poll > 1440):
				raise
		except:
			errorMsgDict['pollingFrequency'] = u"Polling frequency is invalid - enter a valid number (between 1 and 1440)"
		if len(errorMsgDict) > 0:
			return (False, valuesDict, errorMsgDict)
		return (True, valuesDict)

	########################################
	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		if not userCancelled:
			self.debug = valuesDict.get("showDebugInfo", False)
			if self.debug:
				self.debugLog("Debug logging enabled")
			else:
				self.debugLog("Debug logging disabled")

	########################################
	# Called for each enabled Device belonging to plugin
	# Verify connectivity to servers and start polling IMAP/POP servers here
	#
	def deviceStartComm(self, device):
#		self.debugLog("deviceStartComm: \n" + str(device))	
		props = device.pluginProps
		if len(props) < 3:
			self.errorLog("Server \"%s\" is misconfigured - disabling" % device.name)
			indigo.device.enable(device, value=False)
		else:
			if device.id not in self.serverDict:
				self.debugLog("Starting server: " + device.name)
				if device.deviceTypeId == "imapAccount":
					self.serverDict[device.id] = self.IMAPServer(device)
				elif device.deviceTypeId == "popAccount":
					self.serverDict[device.id] = self.POPServer(device)
				elif device.deviceTypeId == "smtpAccount":
					self.serverDict[device.id] = self.SMTPServer(device)
				else:
					self.errorLog("Unknown server device type: " + str(device.deviceTypeId))					
			else:
				self.debugLog("Duplicate Device ID: " + device.name)
			
			
	########################################
	# Terminate communication with servers
	#
	def deviceStopComm(self, device):
		if device.id in self.serverDict:
			del self.serverDict[device.id]
			self.debugLog("Stopping server: " + device.name)
		else:
			self.debugLog("Unknown Device ID: " + device.name)
			

	########################################
	def triggerStartProcessing(self, trigger):
		self.debugLog("Start processing trigger " + str(trigger.id))
		try:
			pass
		except:
			self.errorLog("Error processing trigger %s" % str(trigger.id))

	########################################
	def triggerStopProcessing(self, trigger):
		self.debugLog("Stop processing trigger " + str(trigger.id))
		try:
			pass
		except:
			self.errorLog("Error processing trigger %s" % str(trigger.id))

	########################################
	def pollServers(self):
		self.debugLog("Polling Email Servers")
		for serverId, server in self.serverDict.items():
			server.poll()


	########################################
	# If runConcurrentThread() is defined, then a new thread is automatically created
	# and runConcurrentThread() is called in that thread after startup() has been called.
	#
	# runConcurrentThread() should loop forever and only return after self.stopThread
	# becomes True. If this function returns prematurely then the plugin host process
	# will log an error and attempt to call runConcurrentThread() again after several seconds.
	def runConcurrentThread(self):
		try:
			loopCount = 0
			while True:
				self.pollServers()
				self.debugLog("Next poll in %s minutes" % (self.pluginPrefs['pollingFrequency'],))
				self.sleep(int(self.pluginPrefs['pollingFrequency']) * 60)
		except self.StopThread:
			pass
 
	########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
#		self.debugLog(u"validateDeviceConfigUi: typeId: %s  devId: %s\n%s" % (typeId, str(devId), str(valuesDict)))
		errorsDict = indigo.Dict()
		try:
			pass
		except:
			pass
		if len(errorsDict) > 0:
			return (False, valuesDict, errorsDict)
		return (True, valuesDict)

	########################################
	def validateActionConfigUi(self, valuesDict, typeId, devId):
#		self.debugLog(u"validateActionConfigUi: typeId: %s  devId: %s\n%s" % (typeId, str(devId), str(valuesDict)))
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
		self.debugLog("sendEmailAction called")

		smtpDevice = indigo.devices[pluginAction.deviceId]
		smtpProps = smtpDevice.pluginProps

#		emailTo = self.substitute(pluginAction.props.get("emailTo", ""))
		if "emailTo" in pluginAction.props:
			emailTo =  self.substitute(pluginAction.props["emailTo"])
		else:
			self.errorLog(u"No emailTo property in plugin property dict")
			return
			
#		emailSubject = self.substitute(pluginAction.props.get("emailSubject", ""))
		if "emailSubject" in pluginAction.props:
			emailSubject =  self.substitute(pluginAction.props["emailSubject"])
		else:
			self.errorLog(u"No emailSubject property in plugin property dict")
			return
			
#		emailMessage = self.substitute(pluginAction.props.get("emailMessage", ""))
		if "emailMessage" in pluginAction.props:
			emailMessage =  self.substitute(pluginAction.props["emailMessage"])
		else:
			self.errorLog(u"No emailMessage property in plugin property dict")
			return

		emailCC = self.substitute(pluginAction.props.get("emailCC", ""))
		emailBCC = self.substitute(pluginAction.props.get("emailBCC", ""))

		message = ("From: %s\r\nTo: %s\r\n" % (smtpProps["fromAddress"], emailTo))
		if len(emailCC) > 0:
			message += ("CC: %s\r\n" % emailCC)
		message += ("Subject: %s\r\n\r\n" % emailSubject)
		
		message += emailMessage
		
		toAddresses = emailTo
		if len(emailCC) > 0:
			toAddresses += (", %s" % emailCC)
		if len(emailBCC) > 0:
			toAddresses += (", %s" % emailBCC)

#		To do:  implement a queue for messages in case of connection failure

		try:
			if smtpProps['useSSL']:
				connection = smtplib.SMTP_SSL(smtpProps['hostName'].encode('ascii','ignore'), int(smtpProps['hostPort']))
			else:
				connection = smtplib.SMTP(smtpProps['hostName'].encode('ascii','ignore'), int(smtpProps['hostPort']))
	
			connection.login(smtpProps["serverLogin"],smtpProps["serverPassword"])
			connection.sendmail(smtpProps["fromAddress"], toAddresses, message)
			connection.quit()
			self.debugLog("SMTP connection successful")
			smtpDevice.updateStateOnServer(key="serverStatus", value="Success")

		except Exception, e:
			indigo.activePlugin.errorLog(u"SMTP server connection error: " + str(e))
			smtpDevice.updateStateOnServer(key="serverStatus", value="Failure")	

	########################################
	# Menu Methods
	########################################
	def toggleDebugging(self):
		if self.debug:
			self.debugLog("Turning off debug logging")
			self.pluginPrefs["showDebugInfo"] = False
		else:
			iself.debugLog("Turning on debug logging")
			self.pluginPrefs["showDebugInfo"] = True
		self.debug = not self.debug

