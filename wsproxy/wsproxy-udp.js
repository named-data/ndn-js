/* 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 * Implement WebSocket proxy between ccnd and javascript stack.
 */

var WebSocketServer = require('ws').Server;
var dgram = require('dgram');

var opt = require('node-getopt').create([
  ['c' , 'ccnd=ARG', 'host name or ip of ccnd router'],
  ['p' , 'port=ARG', 'port number on which the proxy will listen'],
  ['m' , 'maxclient=ARG', 'maximum number of concurrent client'],
  ['L' , 'LOG=ARG', 'level of log message display'],
  ['h' , 'help', 'display this help']
])              // create Getopt instance
.bindHelp()     // bind option 'help' to default action
.parseSystem(); // parse command line

var ccndhost = opt.options.ccnd || 'localhost';
var wsport = opt.options.port || 9696;

var wss = new WebSocketServer({port:wsport, host:'0.0.0.0'});   // Set host to '0.0.0.0' so that we can accept connections from anywhere
                                                                // This host has nothing to do with ccndhost.

var MaxNumOfClients = opt.options.maxclient || 40;

var LOG = opt.options.LOG || 1;

if (LOG > 0) console.log('WebSocketServer started...');

wss.on('connection', function(ws) {
	if (LOG > 0) console.log('wss.onconnection: WebSocket client connection received.');
	if (LOG > 0) console.log('wss.onconnection: Number of clients now is ' + wss.clients.length);
	
	if (wss.clients.length > MaxNumOfClients) {
		if (LOG > 0) console.log('wss.onconnection: Max num of clients exceeded. Close WS connection now.');
		ws.terminate();
		return;
	}
	
	var udp = dgram.createSocket("udp4");
	
	/*
	 * According to the email discussion with Michael, when we use
	 * UDP to connect to ccnd, we MUST first send a 'heartbeat' 
	 * UDP packet with 1-byte payload (content of this byte can 
	 * be random). The purpose of this packet is to let ccnd 
	 * mark the incoming FACE as 'friendly' (with CCN_FACE_GG 
	 * flag set). We also need to periodically send this 'heartbeat' 
	 * packet every few seconds to keep ccnd from recycling the UDP 
	 * face. Michael recomended 8 seconds interval. 
	 *      --Wentao
	 */
	// Send 'heartbeat' packet now
	var heartbeat = new Buffer(1);
	heartbeat[0] = 0x21;
	udp.send(heartbeat, 0, 1, 9695, ccndhost, null);
	
	// Schedule a timer to send 'heartbeat' periodically
	var timerID = setInterval(function() {
		if (udp == null || udp == undefined)
			return;
		
		var hb = new Buffer(1);
		hb[0] = 0x21;
		udp.send(hb, 0, 1, 9695, ccndhost, null);
		if (LOG > 1) console.log('UDP heartbeat fired at ccnd.');
	}, 
	8000 // 8000 ms delay
	);
	
	ws.on('message', function(message) {
		if (typeof message == 'string') {
			if (LOG > 2) console.log("ws.onmessage: Message from clinet: " + message);
		}
		else if (typeof message == 'object') {
			// From JS array to Buffer
			var buffer = new Buffer(message);

			if (LOG > 2) {
				var logMsg = 'ws.onmessage: Byte array from client: ';
				for (var i = 0; i < buffer.length; i++)
					logMsg += String.fromCharCode(buffer[i]);
				console.log(logMsg);
			}
			
			udp.send(buffer, 0, buffer.length, 9695, ccndhost, null);
		}
	});
	
	ws.on('close', function() {
		if (LOG > 0) console.log('ws.onclose: WebSocket connection closed. Close UDP connection to ccnd and stop "heartbeat" timer.');
		clearInterval(timerID);
		udp.close();
		udp = null;
	});
	
	udp.on('message', function(msg, rinfo) {
		if (typeof msg == 'object') {
			// From Buffer to ArrayBuffer
			var bytesView = new Uint8Array(msg);
			
			if (LOG > 2) {
				console.log('udp.onmessage: Byte array from server: ');
				console.log('udp.onmessage: bytesView.length ' + bytesView.length);
				var logMsg = "";
				for (var i = 0; i < bytesView.length; i++)
					logMsg += String.fromCharCode(bytesView[i]);
				console.log(logMsg);
			}
			
			ws.send(bytesView.buffer, {binary: true, mask: false});
		}
	});
	
	// Actually the socket close by ccnd will not cause the 'close' event to raise.
	// So this event handle is only called when the client browser shuts down the WS
	// connection, causing ws 'close' event to raise. In that event handle, we explicitly 
	// call udp.close(). So in this function we can do nothing. Anyway, here we clear the 
	// timer and terminate ws for a second time since that will not throw exception. 'ws'
	// will check the 'readyState' before closing, therefore avoids 'close' event loop.
	//     --Wentao
	udp.on('close', function() {
		if (LOG > 0) console.log('udp.onclose: UDP connection to ccnd terminated. Shut down WS connection to client and stop "heartbeat" timer.');
		clearInterval(timerID);
		ws.terminate();
	});
	
	udp.on('error', function() {
		if (LOG > 0) console.log('udp.onerror: Error on UDP connection to ccnd. Shut down WS connection to client and stop "heartbeat" timer.');
		clearInterval(timerID);
		ws.terminate();
	});
});
