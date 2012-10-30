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
            var trimmedSpec = aURI.spec.trim();
    
            var contentChannel;
			var requestContent = function(contentListener) {
                // Set nameString to the URI without the protocol.
                var nameString = trimmedSpec;
                var colonIndex = nameString.indexOf(':');
                if (colonIndex >= 0)
                    nameString = nameString.substr
                        (colonIndex + 1, nameString.length - colonIndex - 1).trim();
                
				var name = new Name(nameString);
                // TODO: Strip off an ending implicit digest before checking the last component?
                var uriEndsWithSequence = endsWithSequence(name);
                
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

                    // Get the URI from the ContentObject including the version.
                    var contentUriSpec;
                    if (!uriEndsWithSequence && endsWithSequence(contentObject.name)) {
                        var nameWithoutSequence = new Name
                            (contentObject.name.components.slice
                             (0, contentObject.name.components.length - 1));
                        contentUriSpec = "ccnx:" + nameWithoutSequence.to_uri();
                    }
                    else
                        contentUriSpec = "ccnx:" + contentObject.name.to_uri();

                    var content = DataUtils.toString(contentObject.content);
                    var contentTypeEtc = getContentTypeAndCharset(contentObject.name);
                    
                    var ioService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
					contentListener.onReceivedContent(content, 
                        contentTypeEtc.contentType, contentTypeEtc.contentCharset, 
                        ioService.newURI(contentUriSpec, aURI.originCharset, null));                    
                    return Closure.RESULT_OK;
				};
			
				ndn.expressInterest(name, new ContentClosure());
			};

			contentChannel = new ContentChannel(aURI, requestContent);
            return contentChannel;
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
 * Scan the name from the last component to the first (skipping special CCNx components)
 *   for a recognized file name extension, and return an object with properties contentType and charset.
 */
function getContentTypeAndCharset(name) {
    for (var i = name.components.length - 1; i >= 0; --i) {
        var component = name.components[i];
        if (component.length <= 0)
            continue;
        
        // Skip special components which just may have ".gif", etc.
        if (component[0] == 0 || component[0] == 0xC0 || component[0] == 0xC1 || 
            (component[0] >= 0xF5 && component[0] <= 0xFF))
            continue;
        
        var str = DataUtils.toString(component).toLowerCase();
        if (str.indexOf(".gif") >= 0) 
            return { contentType: "image/gif", charset: "ISO-8859-1" }
    	else if (str.indexOf(".jpg") >= 0 ||
    			 str.indexOf(".jpeg") >= 0) 
            return { contentType: "image/jpeg", charset: "ISO-8859-1" }
    	else if (str.indexOf(".png") >= 0) 
            return { contentType: "image/png", charset: "ISO-8859-1" }
        else if (str.indexOf(".bmp") >= 0) 
            return { contentType: "image/bmp", charset: "ISO-8859-1" }
    	else if (str.indexOf(".css") >= 0) 
            return { contentType: "text/css", charset: "utf-8" }
    }
    
    // default
    return { contentType: "text/html", charset: "utf-8" };
}

/*
 * Return true if the last component in the name is a sequence..
 */
function endsWithSequence(name) {
    return name.components != null && name.components.length >= 1 &&
        name.components[name.components.length - 1].length >= 1 &&
        name.components[name.components.length - 1][0] == 0;
}