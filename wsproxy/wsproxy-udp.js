#!/usr/bin/env node

/*
 * Implement WebSocket proxy between ndnd and javascript stack.
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Wentao Shang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var WebSocketServer = require('ws').Server;
var dgram = require('dgram');

var opt = require('node-getopt').create([
  ['c' , 'ndnd=ARG', 'host name or ip of ndnd router'],
  ['n' , 'ndndport=ARG', 'port number of the ndnd router'],
  ['p' , 'port=ARG', 'port number on which the proxy will listen'],
  ['m' , 'maxclient=ARG', 'maximum number of concurrent client'],
  ['L' , 'LOG=ARG', 'level of log message display'],
  ['h' , 'help', 'display this help']
])              // create Getopt instance
.bindHelp()     // bind option 'help' to default action
.parseSystem(); // parse command line

var ndndhost = opt.options.ndnd || 'localhost';
var ndndport = opt.options.ndndport || 6363;
var wsport = opt.options.port || 9696;

var wss = new WebSocketServer({port:wsport, host:'0.0.0.0'});   // Set host to '0.0.0.0' so that we can accept connections from anywhere
                                                                // This host has nothing to do with ndndhost.

var MaxNumOfClients = opt.options.maxclient || 40;

var LOG = opt.options.LOG || 1;

if (LOG > 0) console.log('WebSocketServer started...');

wss.on('connection', function(ws)
{
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
   * UDP to connect to ndnd, we MUST first send a 'heartbeat'
   * UDP packet with 1-byte payload (content of this byte can
   * be random). The purpose of this packet is to let ndnd
   * mark the incoming FACE as 'friendly' (with NDN_FACE_GG
   * flag set). We also need to periodically send this 'heartbeat'
   * packet every few seconds to keep ndnd from recycling the UDP
   * face. Michael recomended 8 seconds interval.
   *      --Wentao
   */
  // Send 'heartbeat' packet now
  var heartbeat = new Buffer(1);
  heartbeat[0] = 0x21;
  udp.send(heartbeat, 0, 1, ndndport, ndndhost, null);

  // Schedule a timer to send 'heartbeat' periodically
  var timerID = setInterval(function() {
    if (udp == null || udp == undefined)
      return;

    var hb = new Buffer(1);
    hb[0] = 0x21;
    udp.send(hb, 0, 1, ndndport, ndndhost, null);
    if (LOG > 1) console.log('UDP heartbeat fired at ndnd.');
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

      udp.send(buffer, 0, buffer.length, ndndport, ndndhost, null);
    }
  });

  ws.on('close', function() {
    if (LOG > 0) console.log('ws.onclose: WebSocket connection closed. Close UDP connection to ndnd and stop "heartbeat" timer.');
    clearInterval(timerID);
    udp.close();
    udp = null;
  });

  udp.on('message', function(msg, rinfo) {
    if (msg instanceof Buffer) {
      if (LOG > 2) {
        console.log('udp.onmessage: Byte array from server: ');
        console.log('udp.onmessage: msg.length ' + msg.length);
        var logMsg = "";
        for (var i = 0; i < msg.length; i++)
          logMsg += String.fromCharCode(msg[i]);
        console.log(logMsg);
      }

      ws.send(msg, {binary: true, mask: false});
    }
  });

  // Actually the socket close by ndnd will not cause the 'close' event to raise.
  // So this event handle is only called when the client browser shuts down the WS
  // connection, causing ws 'close' event to raise. In that event handle, we explicitly
  // call udp.close(). So in this function we can do nothing. Anyway, here we clear the
  // timer and terminate ws for a second time since that will not throw exception. 'ws'
  // will check the 'readyState' before closing, therefore avoids 'close' event loop.
  //     --Wentao
  udp.on('close', function() {
    if (LOG > 0) console.log('udp.onclose: UDP connection to ndnd terminated. Shut down WS connection to client and stop "heartbeat" timer.');
    clearInterval(timerID);
    ws.terminate();
  });

  udp.on('error', function() {
    if (LOG > 0) console.log('udp.onerror: Error on UDP connection to ndnd. Shut down WS connection to client and stop "heartbeat" timer.');
    clearInterval(timerID);
    ws.terminate();
  });
});
