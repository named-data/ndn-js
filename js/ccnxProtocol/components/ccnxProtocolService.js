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
                var uriEndsWithSegmentNumber = endsWithSegmentNumber(name);
                
                var ndn = new NDN("lioncub.metwi.ucla.edu");
                ndn.expressInterest(name, new ContentClosure
                    (ndn, contentListener, uriEndsWithSegmentNumber, aURI.originCharset));
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
 * Create a closure for calling expressInterest.
 * contentListener is from the call to requestContent.
 * uriEndsWithSegmentNumber is true if the URI passed to newChannel has a segment number
 *    (used to determine whether to request only that segment number and for updating the URL bar).
 * uriOriginCharset is the charset of the URI passed to newChannel (used for making a new URI)
 */                                                
var ContentClosure = function ContentClosure
        (ndn, contentListener, uriEndsWithSegmentNumber, uriOriginCharset) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.contentListener = contentListener;
    this.uriEndsWithSegmentNumber = uriEndsWithSegmentNumber;
    this.uriOriginCharset = uriOriginCharset;
    this.firstReceivedSegmentNumber = null;
    this.firstReceivedContentObject = null;
}

ContentClosure.prototype.upcall = function(kind, upcallInfo) {
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
        
    var contentObject = upcallInfo.contentObject;
    if (contentObject.content == null) {
        dump("CcnxProtocol.ContentClosure: contentObject.content is null\n");
        return Closure.RESULT_ERR;
    }

    // If !this.uriEndsWithSegmentNumber, we use the segmentNumber to load multiple segments.
    var segmentNumber = null;
    if (!this.uriEndsWithSegmentNumber && endsWithSegmentNumber(contentObject.name)) {
        segmentNumber = DataUtils.bigEndianToUnsignedInt
            (contentObject.name.components[contentObject.name.components.length - 1]);
        if (this.firstReceivedSegmentNumber == null) {
            // This is the first call.
            this.firstReceivedSegmentNumber = segmentNumber;
            if (segmentNumber != 0) {
                // Special case: Save this content object for later and request segment zero.
                this.firstReceivedContentObject = contentObject;
                var componentsForZero = contentObject.name.components.slice
                    (0, contentObject.name.components.length - 1);
                componentsForZero.push([0]);
                this.ndn.expressInterest(new Name(componentsForZero), this); 
                return Closure.RESULT_OK;
            }
        }
    }
    
    if (this.uriEndsWithSegmentNumber || segmentNumber == null || segmentNumber == 0) {
        // This is the first or only segment, so start.
        // Get the URI from the ContentObject including the version.
        var contentUriSpec;
        if (!this.uriEndsWithSegmentNumber && endsWithSegmentNumber(contentObject.name)) {
            var nameWithoutSegmentNumber = new Name
                (contentObject.name.components.slice
                 (0, contentObject.name.components.length - 1));
            contentUriSpec = "ccnx:" + nameWithoutSegmentNumber.to_uri();
        }
        else
            contentUriSpec = "ccnx:" + contentObject.name.to_uri();
    
        var contentTypeEtc = getContentTypeAndCharset(contentObject.name);
        var ioService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
        this.contentListener.onStart(contentTypeEtc.contentType, contentTypeEtc.contentCharset, 
            ioService.newURI(contentUriSpec, this.uriOriginCharset, null));
    }

    this.contentListener.onReceivedContent(DataUtils.toString(contentObject.content));
    
    // Check for the special case if the saved content is for the next segment that we need.
    if (this.firstReceivedContentObject != null && 
        this.firstReceivedSegmentNumber == segmentNumber + 1) {
        // Substitute the saved contentObject send its content and keep going.
        contentObject = this.firstReceivedContentObject;
        segmentNumber = segmentNumber + 1;
        // Clear firstReceivedContentObject to save memory.
        this.firstReceivedContentObject = null;
        
        this.contentListener.onReceivedContent(DataUtils.toString(contentObject.content));        
    }

    var finalSegmentNumber = null;
    if (contentObject.signedInfo != null && contentObject.signedInfo.finalBlockID != null)
        finalSegmentNumber = DataUtils.bigEndianToUnsignedInt(contentObject.signedInfo.finalBlockID);
            
    if (!this.uriEndsWithSegmentNumber &&
        segmentNumber != null && 
        (finalSegmentNumber == null || segmentNumber != finalSegmentNumber)) {
        // Make a name for the next segment and get it.
        var nextSegmentNumber = DataUtils.nonNegativeIntToBigEndian(segmentNumber + 1);
        nextSegmentNumber.unshift(0);
        var components = contentObject.name.components.slice
            (0, contentObject.name.components.length - 1);
        components.push(nextSegmentNumber);
        this.ndn.expressInterest(new Name(components), this);
    }
    else
        // Finished.
        this.contentListener.onStop(); 
        
    return Closure.RESULT_OK;
};
            
 
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
 * Return true if the last component in the name is a segment number..
 */
function endsWithSegmentNumber(name) {
    return name.components != null && name.components.length >= 1 &&
        name.components[name.components.length - 1].length >= 1 &&
        name.components[name.components.length - 1][0] == 0;
}