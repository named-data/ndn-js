/*
 * @author: Jeff Thompson
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
    transport: new XpcomTransport(),

    newURI: function(aSpec, aOriginCharset, aBaseURI)
    {
        // We have to trim now because nsIURI converts spaces to %20 and we can't trim in newChannel.
        var spec = aSpec.trim();
        var preSearch = spec.split('?', 1)[0];
        var searchAndHash = spec.substr(preSearch.length).trim();

        var uri = Cc["@mozilla.org/network/simple-uri;1"].createInstance(Ci.nsIURI);
        uri.spec = preSearch.trim() + searchAndHash;
        return uri;
    },

    newChannel: function(aURI)
    {
        var thisCcnxProtocol = this;
        
        try {            
            // Decode manually since nsIURI doesn't have selectors for hash, etc.
            var spec = aURI.spec.trim();
            var preHash = spec.split('#', 1)[0];
            var hash = spec.substr(preHash.length).trim();
            var preSearch = preHash.split('?', 1)[0];
            var search = preHash.substr(preSearch.length).trim();
            // Set nameString to the preSearch without the protocol.
            var nameString = preSearch.trim();
            if (nameString.indexOf(':') >= 0)
                nameString = nameString.substr(nameString.indexOf(':') + 1).trim();
    
            var template = new Interest(new Name([]));
            // Use the same default as NDN.expressInterest.
            template.interestLifetime = 4200;
            var searchWithoutCcnx = extractCcnxSearch(search, template);
    
            var requestContent = function(contentListener) {                
                var name = new Name(nameString);
                // TODO: Strip off an ending implicit digest before checking the last component?
                var uriEndsWithSegmentNumber = endsWithSegmentNumber(name);
                
                var ndn = new NDN({ host: "lioncub.metwi.ucla.edu", port: 9695,
                      // Use the same transport object each time.
                      getTransport: function() { return thisCcnxProtocol.transport; } });
                ndn.expressInterest(name, 
                    new ContentClosure(ndn, contentListener, uriEndsWithSegmentNumber, 
                            aURI.originCharset, searchWithoutCcnx + hash),
                    template);
            };

            return new ContentChannel(aURI, requestContent);
        } catch (ex) {
            dump("CcnxProtocol.newChannel exception: " + ex + "\n" + ex.stack);
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
 * uriSearchAndHash is the search and hash part of the URI passed to newChannel, including the '?'
 *    and/or '#' but without the interest selector fields.
 */                                                
var ContentClosure = function ContentClosure
        (ndn, contentListener, uriEndsWithSegmentNumber, uriOriginCharset, uriSearchAndHash) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.contentListener = contentListener;
    this.uriEndsWithSegmentNumber = uriEndsWithSegmentNumber;
    this.uriOriginCharset = uriOriginCharset;
    this.uriSearchAndHash = uriSearchAndHash;
    
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
    
        // Include the search and hash.
        contentUriSpec += this.uriSearchAndHash;
    
        var contentTypeEtc = getNameContentTypeAndCharset(contentObject.name);
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
        var segmentNumberPlus1 = DataUtils.nonNegativeIntToBigEndian(segmentNumber + 1);
        // Put a 0 byte in front.
        var nextSegmentNumber = new Uint8Array(segmentNumberPlus1.length + 1);
        nextSegmentNumber.set(segmentNumberPlus1, 1);
        
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
function getNameContentTypeAndCharset(name) {
    var iFileName = name.indexOfFileName();
    if (iFileName < 0)
        // Get the default mime type.
        return MimeTypes.getContentTypeAndCharset("");
    
    return MimeTypes.getContentTypeAndCharset
        (DataUtils.toString(name.components[iFileName]).toLowerCase());
}

/*
 * Return true if the last component in the name is a segment number..
 */
function endsWithSegmentNumber(name) {
    return name.components != null && name.components.length >= 1 &&
        name.components[name.components.length - 1].length >= 1 &&
        name.components[name.components.length - 1][0] == 0;
}

/*
 * Find all search keys starting with "ccnx." and set the attribute in template.
 * Return the search string including the starting "?" but with the "ccnx." keys removed,
 *   or return "" if there are no search terms left.
 */
function extractCcnxSearch(search, template) {
    if (!(search.length >= 1 && search[0] == '?'))
        return search;
    
    var terms = search.substr(1).split('&');
    var i = 0;
    while (i < terms.length) {
        var keyValue = terms[i].split('=');
        var key = keyValue[0].trim();
        if (key.substr(0, 5) == "ccnx.") {
            if (keyValue.length >= 1) {
                var value = keyValue[1].trim();
                var nonNegativeInt = parseInt(value);
                
                if (key == "ccnx.MinSuffixComponents" && nonNegativeInt >= 0)
                    template.minSuffixComponents = nonNegativeInt;
                if (key == "ccnx.MaxSuffixComponents" && nonNegativeInt >= 0)
                    template.maxSuffixComponents = nonNegativeInt;
                if (key == "ccnx.ChildSelector" && nonNegativeInt >= 0)
                    template.childSelector = nonNegativeInt;
                if (key == "ccnx.AnswerOriginKind" && nonNegativeInt >= 0)
                    template.answerOriginKind = nonNegativeInt;
                if (key == "ccnx.Scope" && nonNegativeInt >= 0)
                    template.scope = nonNegativeInt;
                if (key == "ccnx.InterestLifetime" && nonNegativeInt >= 0)
                    template.interestLifetime = nonNegativeInt;
                if (key == "ccnx.PublisherPublicKeyDigest" && nonNegativeInt >= 0)
                    template.publisherPublicKeyDigest = DataUtils.toNumbersFromString(unescape(value));
                if (key == "ccnx.Nonce" && nonNegativeInt >= 0)
                    template.nonce = DataUtils.toNumbersFromString(unescape(value));
                // TODO: handle Exclude.
            }
        
            // Remove the "ccnx." term and don't advance i.
            terms.splice(i, 1);
        }
        else
            ++i;
    }
    
    if (terms.length == 0)
        return "";
    else
        return "?" + terms.join('&');
}