ws-ndn-js
=========

WebSocket proxy server between NDN javascript stack and ccnd

This proxy runs on top of 'node.js'. 'ws' package is required. It listens for WebSocket connection request on port number 9696. Once it receives a incoming connection, it issues a TCP connection to the specified 'ccnd' router (port number 9695). It then translates packet frames from WebSocket to pure TCP byte streams and vice versa.

To run the proxy, simply use the command 'node ws-ndn.js'.

Acknowledgement: this code is extended from Junxiao's WebSocket proxy implementation (https://gist.github.com/3835425).