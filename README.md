
NDN-JS:  A javascript client library for Named Data Networking
--------------------------------------------------------------

NDN-JS is the first native version of the NDN protocol written in JavaScript.  It
implements the NDN-TLV wire format.

The project by the UCLA NDN team - for more information on NDN, see
	http://named-data.net/
	http://ndn.ucla.edu/

See the file [INSTALL](https://github.com/named-data/ndn-js/blob/master/INSTALL) for build and install instructions.

License
-------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
A copy of the GNU Lesser General Public License is in the file COPYING.

Overview
--------
This is a young project, with minimal documentation that we are slowly enhancing.  Please
submit any bugs or issues to the NDN-JS issue tracker:
http://redmine.named-data.net/projects/ndn-js/issues

The primary goal of NDN-JS is to provide a pure Javascript implementation of the NDN API
that enables developers to create browser-based or Node.js-based applications using Named Data Networking.
The approach requires no native code or signed Java applets, and thus can be delivered
over the current web to modern browsers with no hassle for the end user.

Additional goals for the project:
- Websockets transport for the browser (rather than TCP or UDP, which are not directly supported in
the browser).
- Relatively lightweight and compact, to enable efficient use on the web.

The library currently requires a remote NDN forwarder, and has been tested with NFD from the package
https://github.com/named-data/NFD .

Currently, the library has two APIs for developers:

	1. The Javascript API for asynchronous Interest/Data exchange which follows the
       NDN Common Client Libraries API: http://named-data.net/doc/ndn-ccl-api/ . This
       API can be used from the browser or Node.js.
	   The browser uses WebSockets for transport and currently requires a
	   proxy for communication with a remote NDN forwarder.  The Node.js API can use
       the Node.js native support for TCP or Unix sockets.

	2. A Firefox plug-in, which implements an "ndn:/" url scheme
	   following NDNx repository conventions for file retrieval.

By default, both parts of the library connect automatically to a set of proxies and hubs
that are part of the NDN research project's testbed.  http://named-data.net/ndn-testbed/
There are currently no restrictions on non-commercial, research-oriented data exchange on
this testbed. (Contact jburke@remap.ucla.edu for more details.)   The developer can also
specify a local or remote NDN forwarder as well, as an argument to the Face constructor.



JAVASCRIPT API
--------------

See files in js/  and examples in tests/, examples/

NDN-JS currently supports expressing Interests (and receiving data) and publishing Data
(that answers Interests).  This includes encoding and decoding data packets as well as
signing and verifying them using RSA keys.

** NDN connectivity **
The only way (for now) to get connectivity to other NDN nodes is via and NDN forwarder.  For the
Javascript API in the browser, a Websockets proxy that can communicate the target NDN forwarder is currently
required.  NFD supports its own Websockets proxy. For other forwarders, code for such a proxy (using Node.js) is in the wsproxy directory.
The Websocket currently listens on port 9696 and passes messages to the NDN forwarder on
the same host. The Node.js API can use the Node.js native support for TCP (remote or local) or Unix sockets
(to the local NDN forwarder).

** Including the scripts in a web page **
To use NDN-JS in a web page, one of two scripts must be included using a script tag:

ndn.js is a combined library or ndn.min.js is a compressed version of the combined library
which loads faster but doesn't show the original source for debugging.

A web page script tag can load a [released version](https://github.com/named-data/ndn-js/releases) from RawGit.
This URL loads version v0.10.0:

- https://cdn.rawgit.com/named-data/ndn-js/v0.10.0/build/ndn.min.js

For development, see INSTALL for instructions on how to build these files.
Or the latest development snapshot can be downloaded from the `build` directory:

- https://github.com/named-data/ndn-js/raw/master/build/ndn.js
- https://github.com/named-data/ndn-js/raw/master/build/ndn.min.js

** Examples **

*** ndn-ping

You can check out `examples/ndnping/ndn-ping.html` to see an example how to implement ndn-ping in NDN.js

*** Example to retrieve content ***

A simple example of the current API to express an Interest and receive data:

var face = new Face();	// connect to a default hub/proxy

function onData(interest, data) {
  console.log("Received " + data.getName().toUri());
}

face.expressInterest(new Name("/ndn/edu/ucla/remap/ndn-js-test/hello.txt"), onData);

** Example to publish content **

// Note that publishing content requires knowledge of a
// routable prefix for your upstream NDN forwarder.  We are working
// on a way to either obtain that prefix or use the /local
// convention.

For now, see examples/browser/test-publish-async.html



FIREFOX ADD-ON FOR THE NDN PROTOCOL
-----------------------------------

See files in ndn-protocol/

NDN-JS includes a Firefox extension for the ndn protocol built using the Javascript
library.   It currently obtains NDN connectivity through the NDN testbed, but you can
click Set on the NDN Toolbar to change the connected hub.

To install, either download
https://github.com/named-data/ndn-js/raw/master/ndn-protocol.xpi

or use ndn-protocol.xpi in the distribution.  In Firefox, open
Tools > Add-ons.  In the "gear" or "wrench" menu, click Install Add-on From File and open
ndn-protocol.xpi.  (In Firefox for Android, type file: in the address bar and click the
downloaded ndn-protocol.xpi.)  Restart Firefox.

Firefox uses the protocol extension to load any URI starting with ndn.  See this test page for examples:
ndn:/ndn/edu/ucla/remap/demo/ndn-js-test/NDN-Protocol-Examples.html?ndn.ChildSelector=1

When the page is loaded, Firefox updates the address bar with the full matched name from
the retrieved content object including the version, but without the implicit digest or
segment number (see below).

* Interest selectors in the ndn protocol:

You can add interest selectors. For example, this uses 1 to select the "rightmost" child
(latest version):
ndn:/ndn/edu/ucla/remap/ndn-js-test/howdy.txt?my=query&ndn.ChildSelector=1&key=value#ref

The browser loads the latest version and changes the address to:
ndn:/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%EA_%89?my=query&key=value#ref

The child selector was used and removed. Note that the other non-ndn query and
ref "?key=value#ref" are still present, in case they are needed by the web application.

The following selector keys are supported:
ndn.MinSuffixComponent= non-negative int
ndn.MaxSuffixComponents= non-negative int
ndn.ChildSelector= non-negative int
ndn.Scope= non-negative int
ndn.InterestLifetime= non-negative int (milliseconds)
ndn.PublisherPublicKeyDigest= % escaped value
ndn.Nonce= % escaped value
ndn.Exclude= comma-separated list of % escaped values or * for ANY

* Multiple segments in the ndn protocol

A URI for content with multiple segments is handled as follows. If the URI has a segment
number, just retrieve that segment and return the content to the browser.

Otherwise look at the name in the returned ContentObject.  If the returned name has no
segment number, just return the content to the browser. If the name has a segment number
which isn't 0, store it and express an interest for segment 0. Also express an interest for
the highest segment to try to determine the FinalBlockID early. Fetch multiple segments in order and
return each content to the browser (in order) as the arrive until we get the segment for FinalBlockID.

