
NDN.JS:  A javascript client library for Named Data Networking
--------------------------------------------------------------

NDN.JS is the first native version of the NDN protocol written in JavaScript.  It is wire
format compatible with PARC's CCNx. 

The project by the UCLA NDN team - for more information on NDN, see
	http://named-data.net/
	http://ndn.ucla.edu/
	
NDN.JS is open source under a license described in the file COPYING.  While the license
does not require it, we really would appreciate it if others would share their
contributions to the library if they are willing to do so under the same license. 

---

This is a young project, with minimal documentation that we are slowly enhancing.  Please
email Jeff Burke (jburke@remap.ucla.edu) with any questions. 

The primary goal of NDN.JS is to provide a pure Javascript implementation of the NDN API
that enables developers to create browser-based applications using Named Data Networking.
The approach requires no native code or signed Java applets, and thus can be delivered
over the current web to modern browsers with no hassle for the end user.

Additional goals for the project:
- Websockets transport (rather than TCP or UDP, which are not directly supported in
Javascript).
- Relatively lightweight and compact, to enable efficient use on the web.	
- Wire format compatible with PARC's CCNx implementation of NDN.
	
The library currently requires a remote NDN daemon, and has been tested with ccnd, from
the's CCNx package: http://ccnx.org/

Currently, the library has two APIs for developers: 

	1. The Javascript API for asynchronous Interest/Data exchange.
	   This uses WebSockets for transport and currently requires a 
	   proxy for communication with a remote ccnd daemon.

	2. A Firefox plug-in, which implements an "ndn:/" url scheme
	   following CCNx repository conventions for file retrieval.
	   
By default, both parts of the library connect automatically to a set of proxies and hubs
that are part of the NDN research project's testbed.  http://named-data.net/testbed.html
There are currently no restrictions on non-commercial, research-oriented data exchange on
this testbed. (Contact jburke@remap.ucla.edu for more details.)   The developer can also
specify a local or remote ccnd as well, as an argument to the NDN constructor. 

	

JAVASCRIPT API
--------------

See files in js/  and examples in tests/, examples/

NDN.JS currently supports expressing Interests (and receiving data) and publishing Data
(that answers Interests).  This includes encoding and decoding data packets as well as
signing and verifying them using RSA keys.

** NDN connectivity **
The only way (for now) to get connectivity to other NDN nodes is via ccnd.  For the
Javascript API, a Websockets proxy that can communicate the target ccnd is currently
required.  Code for such a proxy (using Node.js) is in the wsproxy directory.  It
currently listens on port 9696 and passes messages (using either TCP or UDP) to ccnd on
the same host. 

** Including the scripts in a web page **
To use NDN.JS in a web page, one of two scripts must be included using a script tag:

ndn-js.js is a combined library (and ndn-js.min.js is a compressed version of the combined library),
designed for efficient distribution.  Bother can be either build in ./build/ndn-js.min.js using 
the following commands:

    ./waf configure
    ./waf

Or downloaded from the `downloads` branch (https://github.com/named-data/ndn-js/tree/downloads):

- http://raw.github.com/named-data/ndn-js/downloads/ndn-js.js
- http://raw.github.com/named-data/ndn-js/downloads/ndn-js.min.js

** Examples **

*** ndn-ping

You can check out `examples/ndn-ping.html` to see an example how to implement ndn-ping in NDN.js

*** Example to retrieve content ***

A simple example of the current API to express an Interest and receive data:

var ndn = new NDN();	// connect to a default hub/proxy
        
var AsyncGetClosure = function AsyncGetClosure() {
    // Inherit from Closure.
    Closure.call(this);
};		
AsyncGetClosure.prototype.upcall = function(kind, upcallInfo) {
    if (kind == Closure.UPCALL_CONTENT) {
        console.log("Received " + upcallInfo.contentObject.name.to_uri());
        console.log(upcallInfo.contentObject.content);
    }
    return Closure.RESULT_OK;
};

ndn.expressInterest(new Name("/ndn/ucla.edu/apps/ndn-js-test/hello.txt"), new
AsyncGetClosure());

** Example to publish content **

// Note that publishing content requires knowledge of a 
// routable prefix for your upstream ccnd.  We are working
// on a way to either obtain that prefix or use the /local
// convention. 

For now, see tests/test-publish-async.html



FIREFOX ADD-ON FOR THE NDN PROTOCOL
-----------------------------------

See files in ndnProtocol/

NDN.JS includes a Firefox extension for the ndn protocol built using the Javascript
library.   It currently obtains NDN connectivity through the NDN testbed, but you can
click Set on the NDN Toolbar to change the connected hub.

To install, either download
https://github.com/named-data/ndn-js/raw/downloads/ndnProtocol.xpi

or use ndnProtocol.xpi from `downloads` branch.  In Firefox, open
Tools > Add-ons.  In the "gear" or "wrench" menu, click Install Add-on From File and open
ndnProtocol.xpi.  (In Firefox for Android, type file: in the address bar and click the
downloaded ndnProtocol.xpi.)  Restart Firefox.

Firefox uses the protocol extension to load any URI starting with ndn.  See this test page for examples

ndn:/ndn/ucla.edu/apps/ndn-js-test/NDNProtocolExamples.html?ndn.ChildSelector=1

When the page is loaded, Firefox updates the address bar with the full matched name from
the retrieved content object including the version, but without the implicit digest or
segment number (see below).

* Interest selectors in the ndn protocol:

You can add interest selectors. For example, this uses 1 to select the "rightmost" child
(latest version).
ndn:/ndn/ucla.edu/apps/ndn-js-test/hello.txt?ndn.ChildSelector=1&key=value#ref

The browser loads the latest version and changes the address to:
ndn:/ndn/ucla.edu/apps/ndn-js-test/hello.txt/%FD%05%0B%16z%22%D1?key=value#ref

The child selector was used and removed. Note that the other non-ndn query values and 
ref "?key=value#ref" are still present, in case they are needed by the web application.

The following selector keys are supported:
ndn.MinSuffixComponent= non-negative int
ndn.MaxSuffixComponents= non-negative int
ndn.ChildSelector= non-negative int
ndn.AnswerOriginKind= non-negative int
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

