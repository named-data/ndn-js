/*
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * This is the ccnx protocol handler for NDN.
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
            // Save the mostRecentWindow from the moment of newChannel.
    		var wm = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);
    		var mostRecentWindow = wm.getMostRecentWindow("navigator:browser");
    
			var requestContent = function(contentListener) {
				var name = aURI.spec.split(":")[1];
			    // 131.179.141.18 is lioncub.metwi.ucla.edu .
				var ndn = new NDN('131.179.141.18');
				
				var ContentClosure = function ContentClosure() {
                    // Inherit from Closure.
                    Closure.call(this);
                }
                ContentClosure.prototype.upcall = function(kind, upcallInfo) {
                    if (!(kind == Closure.UPCALL_CONTENT ||
                          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
                        // The upcall is not for us.
                        return Closure.RESULT_ERR;
                        
                    var contentObject = upcallInfo.contentObject;
                    if (contentObject.content == null) {
                        dump("CcnxProtocol.newChannel: contentObject.content is null\n");
                        return Closure.RESULT_ERR;
                    }
                        
                    var content = DataUtils.toString(contentObject.content);
					// TODO: Should look at the returned Name to get contentType. For now,
					//   just look at the original name.
                    var contentTypeAndCharset = getContentTypeAndCharset(name);						
					contentListener.onReceivedContent(content, 
                        contentTypeAndCharset.contentType, contentTypeAndCharset.contentCharset);
                    
                    // Assume that onReceivedContent sends all the content immediately and that
                    //   the URLBar is updated if the content is for the main window.
                    var urlBar = mostRecentWindow.gURLBar;
                    
                    return Closure.RESULT_OK;
				};
			
				ndn.expressInterest(new Name(name), new ContentClosure());
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
 
/*
 * Based on name, return and object with properties contentType and charset.
 */
function getContentTypeAndCharset(name) {
    // Set up defaults.
    var contentType = "text/html";
	var charset = "utf-8";

	var nameLowerCase = name.toLowerCase();
	if (nameLowerCase.indexOf(".gif") >= 0) {
	    contentType = "image/gif";
		charset = "ISO-8859-1";
	}
	else if (nameLowerCase.indexOf(".jpg") >= 0 ||
			 nameLowerCase.indexOf(".jpeg") >= 0) {
		contentType = "image/jpeg";
		charset = "ISO-8859-1";
	}
	else if (nameLowerCase.indexOf(".png") >= 0) {
		contentType = "image/png";
		charset = "ISO-8859-1";
	}
	else if (nameLowerCase.indexOf(".bmp") >= 0) {
		contentType = "image/bmp";
		charset = "ISO-8859-1";
	}
	else if (nameLowerCase.indexOf(".css") >= 0)
		contentType = "text/css";
    
    return {
        contentType: contentType,
        charset: charset
    };
}
