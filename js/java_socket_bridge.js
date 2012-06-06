/*
 * @author: ucla-cs
 * This class represents Interest Objects
 */


//var ccnxnodename = unescape('%E0%A0%1E%099h%F9t%0C%E7%F46%1B%AB%F5%BB%05%A4%E5Z%AC%A5%E5%8Fs%ED%DE%B8%E0%13%AA%8F');


var LOG = 0;


var java_socket_bridge_ready_flag = false;

var ndnport =null;
var ndnurl=null;

var registeredPrefixes ={};

/**
 * Add a trim funnction for Strings
 */
String.prototype.trim = function() {
	return this.replace(/^\s+|\s+$/g, "");
};


// Applet reports it is ready to use
function java_socket_bridge_ready(){
	console.log('APPLET LOADED');
	java_socket_bridge_ready_flag = true;
	
}

// Send Test Interest
function get(host,port,data){
	if(java_socket_bridge_ready_flag){
		return get_java_socket_bridge().get(host,port,data,1000);
	}
	else{
		on_socket_error("Java Socket Bridge send Interest until the applet has loaded");
	}
}


// Send Test Interest
function put(host,port,data,name,toReturn){
	
	if(java_socket_bridge_ready_flag){ 
		return get_java_socket_bridge().put(host,port,data,name,toReturn);
	}
	else{
		on_socket_error("Java Socket Bridge send Interest until the applet has loaded");
	}
}

function on_socket_received_interest(hex,name){
	
	if(LOG>3)console.log('received interest from host'+ host +':'+port+' with name '+name);
	
	if(LOG>3)console.log('DATA ');
	
	if(LOG>3)console.log(hex);
	
	interest = decodeHexInterest(hex);
	
	console.log('SUCCESSFULLY PARSED INTEREST');
	
	console.log('CREATING ANSWER');
	var si = new SignedInfo();
	si.setFields();
	
	var answer = toNumbersFromString('WORLD');

	var co = new ContentObject(new ContentName(name),si,answer,new Signature()); 
	co.sign();
	
	
	var outputHex = encodeToHexContentObject(co);
	
	console.log('SENDING ANSWER');

	return get_java_socket_bridge().putAnswer(outputHex,name);
}

// Get something from the socket
function on_socket_get(message){}

// Report an error
function on_socket_error(message){
	alert('Received error message \n' +message);
}

// Get the applet object
function get_java_socket_bridge(){
	return document.getElementById('JavaSocketBridge');
}