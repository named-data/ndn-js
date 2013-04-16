/* 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 * Implement WebSocket proxy between ccnd and javascript stack.
 */

var WebSocketServer = require('ws').Server;
var net = require('net');

var opt = require('node-getopt').create([
  ['c' , 'ccnd=ARG', 'host name or ip of ccnd router'],
  ['p' , 'port=ARG', 'port number on which the proxy will listen'],
  ['m' , 'maxclient=ARG', 'maximum number of concurrent client'],
  ['L' , 'LOG=ARG', 'level of log message display'],
  ['h' , 'help', 'display this help']
])              // create Getopt instance
.bindHelp()     // bind option 'help' to default action
.parseSystem(); // parse command line

//console.log(opt);

var ccndhost = opt.options.ccnd || 'localhost';
//console.log(ccndhost);

var wsport = opt.options.port || 9696;
//console.log(wsport);

var wss = new WebSocketServer({port:wsport, host:'0.0.0.0'});   // Set host to '0.0.0.0' so that we can accept connections from anywhere
                                                                // This host has nothing to do with ccndhost.

var MaxNumOfClients = opt.options.maxclient || 40;
//console.log(MaxNumOfClients);

var LOG = opt.options.LOG || 1;
//console.log(LOG);

if (LOG > 0) console.log('WebSocketServer started...');

wss.on('connection', function(ws) {
	if (LOG > 0) console.log('WebSocket client connection received.');
	if (LOG > 0) console.log('Number of clients now is ' + wss.clients.length);
	
	if (wss.clients.length > MaxNumOfClients) {
		if (LOG > 0) console.log('Max num of clients exceeded. Close WS connection now.');
		ws.terminate();
		return;
	}
	
	var sock_ready = false;
	var ws_ready = true;
	var send_queue = [];
	var sock = net.connect({port: 9695, host: ccndhost});
	
	ws.on('message', function(message) {
		if (typeof message == 'string') {
			if (LOG > 1) console.log("Message from clinet: " + message);
		}
		else if (typeof message == 'object') {
			var bytesView = new Buffer(message);

			if (LOG > 1) {
				var logMsg = 'Byte array from client: ';
				for (var i = 0; i < bytesView.length; i++)
					logMsg += String.fromCharCode(bytesView[i]);
				console.log(logMsg);
			}
			
			if (sock_ready) {
				sock.write(bytesView);
			} else {
				send_queue.push(message);
			}
		}
	});
	
	ws.on('close', function() {
		if (LOG > 0) console.log('WebSocket connection closed.');
		ws_ready = false;
		sock.end();
	});
	
	sock.on('connect', function() {
		while (send_queue.length > 0) {
			var message = send_queue.shift();
			sock.write(message);
		}
		sock_ready = true;
		if (LOG > 0) console.log('ccnd socket connection ready.');
	});
	
	sock.on('data', function(data) {
		if (typeof data == 'object') {
			var bytesView = new Buffer(data);
			
			if (LOG > 1) {
				console.log('Byte array from server: ');
				var logMsg = "";
				for (var i = 0; i < bytesView.length; i++)
					logMsg += String.fromCharCode(bytesView[i]);
				console.log(logMsg);
			}
			
			if (ws_ready == true) {
				ws.send(bytesView, {binary: true, mask: false});
			}
		}
	});
	
	sock.on('end', function() {
		if (LOG > 0) console.log('TCP connection terminated by ccnd. Shut down WS connection to client.');
		ws.terminate();
	});
	
	sock.on('error', function() {
		if (LOG > 0) console.log('Error on TCP connection to ccnd. Shut down WS connection to client.');
		ws.terminate();
	});
});
