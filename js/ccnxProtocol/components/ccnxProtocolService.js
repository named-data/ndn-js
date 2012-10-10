/*
 * @author: ucla-cs
 * This is the ccnx protocol handler.
 * Protocol handling code derived from http://mike.kaply.com/2011/01/18/writing-a-firefox-protocol-handler/
 */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

const nsIProtocolHandler = Ci.nsIProtocolHandler;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/ContentChannel.jsm");

function CcnxProtocol() {
}

CcnxProtocol.prototype = {
	scheme: "ccnx",
	protocolFlags: nsIProtocolHandler.URI_NORELATIVE |
                   nsIProtocolHandler.URI_NOAUTH |
                   nsIProtocolHandler.URI_LOADABLE_BY_ANYONE,

	newURI: function(aSpec, aOriginCharset, aBaseURI)
	{
		var uri = Cc["@mozilla.org/network/simple-uri;1"].createInstance(Ci.nsIURI);
		uri.spec = aSpec;
		return uri;
	},

	newChannel: function(aURI)
	{
		try {
			var requestContent = function(contentListener) {
				var interest = aURI.spec.split(":")[1];
			    // 131.179.141.18 is lioncub.metwi.ucla.edu .
				var ndn = new NDN('131.179.141.18');
				
				var coListener = {
					onReceivedContentObject : function(contentObject) {
						// Set up defaults.
						var content = "";
						var contentType = "text/html";
						var contentCharset = "utf-8";

						// TODO: Need to check the signature, confirm that the name matches, etc.
						if (contentObject.content != null) {
							content = DataUtils.toString(contentObject.content);
							// TODO: Should look at the returned Name to get contentType. For now,
							//   just look for an image file extension in the original interest.
							var interestLowerCase = interest.toLowerCase();
							if (interestLowerCase.indexOf(".gif") >= 0) {
								contentType = "image/gif";
								contentCharset = "ISO-8859-1";
							}
							else if (interestLowerCase.indexOf(".jpg") >= 0 ||
									 interestLowerCase.indexOf(".jpeg") >= 0) {
								contentType = "image/jpeg";
								contentCharset = "ISO-8859-1";
							}
							else if (interestLowerCase.indexOf(".png") >= 0) {
								contentType = "image/png";
								contentCharset = "ISO-8859-1";
							}
							else if (interestLowerCase.indexOf(".bmp") >= 0) {
								contentType = "image/bmp";
								contentCharset = "ISO-8859-1";
							}
						}
						
						contentListener.onReceivedContent(content, contentType, contentCharset);
					}
				};
			
				ndn.getAsync(interest, coListener);
			};

			return new ContentChannel(aURI, requestContent);
		} catch (ex) {
			dump("CcnxProtocol.newChannel exception: " + ex + "\n");
		}
	},

	classDescription: "ccnx Protocol Handler",
	contractID: "@mozilla.org/network/protocol;1?name=" + "ccnx",
	classID: Components.ID('{8122e660-1012-11e2-892e-0800200c9a66}'),
	QueryInterface: XPCOMUtils.generateQI([Ci.nsIProtocolHandler])
}

if (XPCOMUtils.generateNSGetFactory)
	var NSGetFactory = XPCOMUtils.generateNSGetFactory([CcnxProtocol]);
else
	var NSGetModule = XPCOMUtils.generateNSGetModule([CcnxProtocol]);
 

