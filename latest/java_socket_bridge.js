// Global variables
var java_socket_bridge_ready_flag = false;

var ndnport =null;
var ndnurl=null;

// Applet reports it is ready to use
function java_socket_bridge_ready(){
	java_socket_bridge_ready_flag = true;
}

function createRoute(url, port){
	ndnport = port;
	ndnurl=url;
}

// Connect to a given url and port
function queryPrefix(message){
	if(ndnport!=null && ndnurl!=null){
		var newMessage ='';
		
		enc = new BinaryXMLEncoder();
 
		//encoder.beginEncoding();
    
		
		int = new Interest(new ContentName(['PARC','%00','%01','%02']));
		
		int.encode(enc);
		
		var hex = byte2hex(enc.ostream);
		
		console.log('Conect and start '+ ndnurl +':'+ndnport+'-'+message);
		
		return get_java_socket_bridge().connectAndStart(ndnurl,ndnport,message);
	}
	else{
		console.log('ERROR URL OR PORT NOT SET');
		return '';
	}	

}


function byte2hex(bytearray){var result = [];
	var length = bytearray.length;
	for (var i = 0;i < length;++i) {
	    result.push(AddFillerLeft(bytearray[i].toString(16).toUpperCase(), '0', 2));
	}
	return result.join('');
}
// Get something from the socket
function on_socket_get(message){}

// Report an error
function on_socket_error(message){
	alert(message);
}

// Get the applet object
function get_java_socket_bridge(){
	return document.getElementById('JavaSocketBridge');
}