wsproxy
=======

WebSocket proxy server between NDN javascript stack and ccnd.

This proxy runs on top of 'node.js'. 'ws' and 'node-getopt' packages are required. It listens for WebSocket connection request on port number 9696. Once it receives a incoming connection, it issues a TCP connection to the specified 'ccnd' router (port number 9695). It then translates packet frames from WebSocket to pure TCP byte streams and vice versa.

Installation guide:

1) node.js: go to http://nodejs.org/ to download and install node.js;

2) ws package: use command 'npm install ws' or go to https://github.com/einaros/ws for more information;

3) node-getopt package: use command 'npm install node-getopt' or go to https://npmjs.org/package/node-getopt for more information.


To run the proxy, simply use the command 'node wsproxy-tcp.js' or 'node wsproxy-udp.js'.

To specify remote ccnd router's hostname or ip address, use option '-c x.x.x.x'. Default is 'localhost'.

To specify the port number on which the proxy will listen, use option '-p xxxx'. Default is 9696.

To specify maximum number of concurrent clients, use option '-m N'. Default is 40.

To specify the level of log info display, use option '-L x'. x=0 means no output; x=1 will log connection startup and close; x=2 will log contents of all messages that flow across the proxy. Default is 1.

Example: to setup UDP connection to ccnd router 192.168.1.51 with max client number 50 and log level 2, use the command:

node wsproxy-udp.js -c 192.168.1.51 -m 50 -L 2

Acknowledgement: this code is extended from Junxiao's WebSocket proxy implementation (https://gist.github.com/3835425).