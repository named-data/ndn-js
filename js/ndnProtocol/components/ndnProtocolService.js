/*
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This is the ndn protocol handler.
 * Protocol handling code derived from http://mike.kaply.com/2011/01/18/writing-a-firefox-protocol-handler/
 */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

const nsIProtocolHandler = Ci.nsIProtocolHandler;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/ContentChannel.jsm");
Components.utils.import("chrome://modules/content/NdnProtocolInfo.jsm");

function NdnProtocol() {
    // TODO: Remove host: null when null is the default.
    this.ndn = new NDN({ getTransport: function() { return new XpcomTransport(); }, host: null });
}

NdnProtocol.prototype = {
    scheme: "ndn",
    protocolFlags: nsIProtocolHandler.URI_NORELATIVE |
                   nsIProtocolHandler.URI_NOAUTH |
                   nsIProtocolHandler.URI_LOADABLE_BY_ANYONE,

    newURI: function(aSpec, aOriginCharset, aBaseURI)
    {
        var uri = Cc["@mozilla.org/network/simple-uri;1"].createInstance(Ci.nsIURI);

        // We have to trim now because nsIURI converts spaces to %20 and we can't trim in newChannel.
        var uriParts = splitUri(aSpec);
        if (aBaseURI == null || uriParts.name.length < 1 || uriParts.name[0] == '/')
            // Just reconstruct the trimmed URI.
            uri.spec = "ndn:" + uriParts.name + uriParts.search + uriParts.hash;
        else {
            // Make a URI relative to the base name up to the file name component.
            var baseUriParts = splitUri(aBaseURI.spec);
            var baseName = new Name(baseUriParts.name);
            var iFileName = baseName.indexOfFileName();
            
            var relativeName = uriParts.name;
            // Handle ../
            while (true) {
                if (relativeName.substr(0, 2) == "./")
                    relativeName = relativeName.substr(2);
                else if (relativeName.substr(0, 3) == "../") {
                    relativeName = relativeName.substr(3);
                    if (iFileName > 0)
                        --iFileName;
                }
                else
                    break;
            }
            
            var prefixUri = "/";
            if (iFileName > 0)
                prefixUri = new Name(baseName.components.slice(0, iFileName)).to_uri() + "/";
            uri.spec = "ndn:" + prefixUri + relativeName + uriParts.search + uriParts.hash;
        }
        
        return uri;
    },

    newChannel: function(aURI)
    {
        var thisNdnProtocol = this;
        
        try {            
            var uriParts = splitUri(aURI.spec);
    
            var template = new Interest(new Name([]));
            // Use the same default as NDN.expressInterest.
            template.interestLifetime = 4000; // milliseconds
            var searchWithoutNdn = extractNdnSearch(uriParts.search, template);
            
            var segmentTemplate = new Interest(new Name([]));
            // Only use the interest selectors which make sense for fetching further segments.
            segmentTemplate.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
            segmentTemplate.scope = template.scope;
            segmentTemplate.interestLifetime = template.interestLifetime;
    
            var requestContent = function(contentListener) {                
                var name = new Name(uriParts.name);
                // TODO: Strip off an ending implicit digest before checking the last component?
                var uriEndsWithSegmentNumber = endsWithSegmentNumber(name);
                
                // Use the same NDN object each time.
                thisNdnProtocol.ndn.expressInterest(name, 
                    new ContentClosure(thisNdnProtocol.ndn, contentListener, uriEndsWithSegmentNumber, 
                            aURI.originCharset, searchWithoutNdn + uriParts.hash, segmentTemplate),
                    template);
            };

            return new ContentChannel(aURI, requestContent);
        } catch (ex) {
            dump("NdnProtocol.newChannel exception: " + ex + "\n" + ex.stack);
        }
    },

    classDescription: "ndn Protocol Handler",
    contractID: "@mozilla.org/network/protocol;1?name=" + "ndn",
    classID: Components.ID('{8122e660-1012-11e2-892e-0800200c9a66}'),
    QueryInterface: XPCOMUtils.generateQI([Ci.nsIProtocolHandler])
};

if (XPCOMUtils.generateNSGetFactory)
    var NSGetFactory = XPCOMUtils.generateNSGetFactory([NdnProtocol]);
else
    var NSGetModule = XPCOMUtils.generateNSGetModule([NdnProtocol]);
                
/*
 * Create a closure for calling expressInterest.
 * contentListener is from the call to requestContent.
 * uriEndsWithSegmentNumber is true if the URI passed to newChannel has a segment number
 *    (used to determine whether to request only that segment number and for updating the URL bar).
 * uriOriginCharset is the charset of the URI passed to newChannel (used for making a new URI)
 * uriSearchAndHash is the search and hash part of the URI passed to newChannel, including the '?'
 *    and/or '#' but without the interest selector fields.
 * segmentTemplate is the template used in expressInterest to fetch further segments.
 */                                                
var ContentClosure = function ContentClosure
        (ndn, contentListener, uriEndsWithSegmentNumber, uriOriginCharset, uriSearchAndHash, 
         segmentTemplate) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.contentListener = contentListener;
    this.uriEndsWithSegmentNumber = uriEndsWithSegmentNumber;
    this.uriOriginCharset = uriOriginCharset;
    this.uriSearchAndHash = uriSearchAndHash;
    this.segmentTemplate = segmentTemplate;
    
    this.firstReceivedSegmentNumber = null;
    this.firstReceivedContentObject = null;
    this.contentSha256 = null;
};

ContentClosure.prototype.upcall = function(kind, upcallInfo) {
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
        
    var contentObject = upcallInfo.contentObject;
    if (contentObject.content == null) {
        dump("NdnProtocol.ContentClosure: contentObject.content is null\n");
        return Closure.RESULT_ERR;
    }
    
    // Now that we're connected, report the host and port.
    setConnectedNdnHub(this.ndn.host, this.ndn.port);

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
                this.ndn.expressInterest(new Name(componentsForZero), this, this.segmentTemplate); 
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
                (contentObject.name.components.slice(0, contentObject.name.components.length - 1));
            contentUriSpec = "ndn:" + nameWithoutSegmentNumber.to_uri();
        }
        else
            contentUriSpec = "ndn:" + contentObject.name.to_uri();
    
        // Include the search and hash.
        contentUriSpec += this.uriSearchAndHash;
    
        var contentTypeEtc = getNameContentTypeAndCharset(contentObject.name);
        var ioService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
        this.contentListener.onStart(contentTypeEtc.contentType, contentTypeEtc.contentCharset, 
            ioService.newURI(contentUriSpec, this.uriOriginCharset, null));
            
        this.contentSha256 = new Sha256();
    }

    this.contentListener.onReceivedContent(DataUtils.toString(contentObject.content));
    this.contentSha256.update(contentObject.content);
    
    // Check for the special case if the saved content is for the next segment that we need.
    if (this.firstReceivedContentObject != null && 
        this.firstReceivedSegmentNumber == segmentNumber + 1) {
        // Substitute the saved contentObject send its content and keep going.
        contentObject = this.firstReceivedContentObject;
        segmentNumber = segmentNumber + 1;
        // Clear firstReceivedContentObject to save memory.
        this.firstReceivedContentObject = null;
        
        this.contentListener.onReceivedContent(DataUtils.toString(contentObject.content));        
        this.contentSha256.update(contentObject.content);
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
        this.ndn.expressInterest(new Name(components), this, this.segmentTemplate);
    }
    else {
        // Finished.
        this.contentListener.onStop();
        var nameContentDigest = contentObject.name.getContentDigestValue();
        if (nameContentDigest != null &&
            !DataUtils.arraysEqual(nameContentDigest, this.contentSha256.finalize()))
            // TODO: How to show the user an error for invalid digest?
            dump("Content does not match digest in name " + contentObject.name.to_uri());
    }
        
    return Closure.RESULT_OK;
};
             
/*
 * Scan the name from the last component to the first (skipping special name components)
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
 * Find all search keys starting with "ndn." and set the attribute in template.
 * Return the search string including the starting "?" but with the "ndn." keys removed,
 *   or return "" if there are no search terms left.
 */
function extractNdnSearch(search, template) {
    if (!(search.length >= 1 && search[0] == '?'))
        return search;
    
    var terms = search.substr(1).split('&');
    var i = 0;
    while (i < terms.length) {
        var keyValue = terms[i].split('=');
        var key = keyValue[0].trim();
        if (key.substr(0, 4) == "ndn.") {
            if (keyValue.length >= 1) {
                var value = keyValue[1].trim();
                var nonNegativeInt = parseInt(value);
                
                if (key == "ndn.MinSuffixComponents" && nonNegativeInt >= 0)
                    template.minSuffixComponents = nonNegativeInt;
                if (key == "ndn.MaxSuffixComponents" && nonNegativeInt >= 0)
                    template.maxSuffixComponents = nonNegativeInt;
                if (key == "ndn.ChildSelector" && nonNegativeInt >= 0)
                    template.childSelector = nonNegativeInt;
                if (key == "ndn.AnswerOriginKind" && nonNegativeInt >= 0)
                    template.answerOriginKind = nonNegativeInt;
                if (key == "ndn.Scope" && nonNegativeInt >= 0)
                    template.scope = nonNegativeInt;
                if (key == "ndn.InterestLifetime" && nonNegativeInt >= 0)
                    template.interestLifetime = nonNegativeInt;
                if (key == "ndn.PublisherPublicKeyDigest" && nonNegativeInt >= 0)
                    template.publisherPublicKeyDigest = DataUtils.toNumbersFromString(unescape(value));
                if (key == "ndn.Nonce" && nonNegativeInt >= 0)
                    template.nonce = DataUtils.toNumbersFromString(unescape(value));
                // TODO: handle Exclude.
            }
        
            // Remove the "ndn." term and don't advance i.
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
