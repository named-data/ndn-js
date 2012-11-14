var WebSocketServer = require('ws').Server;
var dgram = require('dgram');

var ccndhost = 'localhost';

var wss = new WebSocketServer({port:9696, host:ccndhost});

var MaxNumOfClients = 2;

wss.on('connection', function(ws) {
	console.log('wss.onconnection: WebSocket client connection received.');
	console.log('wss.onconnection: Number of clients now is ' + wss.clients.length);
	
	if (wss.clients.length > MaxNumOfClients) {
		console.log('wss.onconnection: Max num of clients exceeded. Close WS connection now.');
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
		//console.log('UDP heartbeat fired at ccnd.');
	}, 
	8000 // 8000 ms delay
	);
	
	ws.on('message', function(message) {
		if (typeof message == 'string')
			console.log("ws.onmessage: Message from clinet: " + message);
		else if (typeof message == 'object') {
			// From JS array to Buffer
			var buffer = new Buffer(message);

			var logMsg = 'ws.onmessage: Byte array from client: ';
			for (var i = 0; i < buffer.length; i++)
				logMsg += String.fromCharCode(buffer[i]);
			console.log(logMsg);
			
			udp.send(buffer, 0, buffer.length, 9695, ccndhost, null);
			console.log('ws.onmessage: udp.send() returned.');
		}
	});
	
	ws.on('close', function() {
		console.log('ws.onclose: WebSocket connection closed. Close UDP connection to ccnd and stop "heartbeat" timer.');
		clearInterval(timerID);
		udp.close();
		udp = null;
	});
	
	udp.on('message', function(msg, rinfo) {
		if (typeof msg == 'object') {
			// From Buffer to ArrayBuffer
			var bytesView = new Uint8Array(msg);
			
			console.log('udp.onmessage: Byte array from server: ');
			console.log('udp.onmessage: bytesView.length ' + bytesView.length);
			var logMsg = "";
			for (var i = 0; i < bytesView.length; i++)
				logMsg += String.fromCharCode(bytesView[i]);
			console.log(logMsg);
			
			ws.send(bytesView.buffer, {binary: true, mask: false});
			console.log('udp.onmessage: ws.send() returned.');
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
		console.log('udp.onclose: UDP connection to ccnd terminated. Shut down WS connection to client and stop "heartbeat" timer.');
		clearInterval(timerID);
		ws.terminate();
	});
	
	udp.on('error', function() {
		console.log('udp.onerror: Error on UDP connection to ccnd. Shut down WS connection to client and stop "heartbeat" timer.');
		clearInterval(timerID);
		ws.terminate();
	});
});
