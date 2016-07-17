# BetterEmail

Plugin for the Indigo Home Automation system.

This plugin provides enhances capabilities for sending and receiving email from within Indigo.


### Broadcast Messages

    PluginID: com.flyingdiver.indigoplugin.betteremail

    MessageType: messageReceived 
    Returns dictionary:
    {
    	'messageFrom':  	<text string>,
		'messageTo': 		<text string>,
		'messageSubject': 	<text string>,
		'messageText': 		<text string>
	}

    MessageType: messageSent
    Returns dictionary:
    {
    	'messageFrom':  	<text string>,
		'messageTo': 		<text string>,
		'messageSubject': 	<text string>,
		'messageText': 		<text string>
	}
