var WebSocketServer = require('ws').Server;
var net = require('net');

var wss = new WebSocketServer({port:9696, host:'0.0.0.0'});

var MaxNumOfClients = 2;

wss.on('connection', function(ws) {
	console.log('WebSocket client connection received.');
	console.log('Number of clients now is ' + wss.clients.length);
	
	if (wss.clients.length > MaxNumOfClients) {
		console.log('Max num of clients exceeded. Close WS connection now.');
		ws.terminate();
		return;
	}
	
	var sock_ready = false;
	var send_queue = [];
	var sock = net.createConnection(9695);
	
	ws.on('message', function(message) {
		if (typeof message == 'string')
			console.log("Message from clinet: " + message);
		else if (typeof message == 'object') {
			var bytesView = new Uint8Array(message);

			var logMsg = 'Byte array from client: ';
			for (var i = 0; i < bytesView.length; i++)
				logMsg += String.fromCharCode(bytesView[i]);
			console.log(logMsg);
			
			if (sock_ready) {
				sock.write(bytesView.buffer);
				console.log('sock.write() returned.');
			} else {
				send_queue.push(message);
			}
		}
	});
	
	ws.on('close', function() {
		console.log('WebSocket connection closed.');
		sock.end();
	});
	
	sock.on('connect', function() {
		while (send_queue.length > 0) {
			var message = send_queue.shift();
			sock.write(message);
		}
		sock_ready = true;
		console.log('ccnd socket connection ready.');
	});
	
	sock.on('data', function(data) {
		if (typeof data == 'object') {
			var bytesView = new Uint8Array(data);
			
			console.log('Byte array from server: ');
			var logMsg = "";
			for (var i = 0; i < bytesView.length; i++)
				logMsg += String.fromCharCode(bytesView[i]);
			console.log(logMsg);
			
			ws.send(bytesView.buffer, {binary: true, mask: false});
			console.log('ws.send() returned.');
		}
	});
	
	sock.on('end', function() {
		console.log('TCP connection terminated by ccnd. Shut down WS connection to client.');
		ws.terminate();
	});
	
	sock.on('error', function() {
		console.log('Error on TCP connection to ccnd. Shut down WS connection to client.');
		ws.terminate();
	});
});
