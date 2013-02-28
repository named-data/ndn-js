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
    this.ndn = new NDN({ getTransport: function() { return new XpcomTransport(); }, 
                       verify: false });
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
        var uriParts = NdnProtocolInfo.splitUri(aSpec);
        if (aBaseURI == null || uriParts.name.length < 1 || uriParts.name[0] == '/')
            // Just reconstruct the trimmed URI.
            uri.spec = "ndn:" + uriParts.name + uriParts.search + uriParts.hash;
        else {
            // Make a URI relative to the base name up to the file name component.
            var baseUriParts = NdnProtocolInfo.splitUri(aBaseURI.spec);
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
            var uriParts = NdnProtocolInfo.splitUri(aURI.spec);
    
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
                // Use the same NDN object each time.
                thisNdnProtocol.ndn.expressInterest(name, new ExponentialReExpressClosure 
                    (new ContentClosure(thisNdnProtocol.ndn, contentListener, name, 
                            aURI, searchWithoutNdn + uriParts.hash, segmentTemplate)),
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
 * uriName is the name in the URI passed to newChannel (used in part to determine whether to request 
 *   only that segment number and for updating the URL bar).
 * aURI is the URI passed to newChannel.
 * uriSearchAndHash is the search and hash part of the URI passed to newChannel, including the '?'
 *    and/or '#' but without the interest selector fields.
 * segmentTemplate is the template used in expressInterest to fetch further segments.
 * The uses ExponentialReExpressClosure in expressInterest to re-express if fetching a segment times out.
 */                                                
var ContentClosure = function ContentClosure
      (ndn, contentListener, uriName, aURI, uriSearchAndHash, segmentTemplate) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.contentListener = contentListener;
    this.uriName = uriName;
    this.aURI = aURI;
    this.uriSearchAndHash = uriSearchAndHash;
    this.segmentTemplate = segmentTemplate;
    
    this.segmentStore = new SegmentStore();
    this.contentSha256 = new Sha256();
    this.didRequestFinalSegment = false;
    this.finalSegmentNumber = null;
    this.didOnStart = false;
    this.uriEndsWithSegmentNumber = endsWithSegmentNumber(uriName);
};

ContentClosure.prototype.upcall = function(kind, upcallInfo) {
  try {
    // Assume this is only called once we're connected, report the host and port.
    NdnProtocolInfo.setConnectedNdnHub(this.ndn.host, this.ndn.port);
    
    if (this.contentListener.done)
        // We are getting unexpected extra results.
        return Closure.RESULT_ERR;
    
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
        if (!this.didOnStart) {
            // We have not received a segments to start the content yet, so assume the URI can't be fetched.
            this.contentListener.onStart("text/plain", "utf-8", this.aURI);
            this.contentListener.onReceivedContent
                ("The latest interest timed out after " + upcallInfo.interest.interestLifetime + " milliseconds.");
            this.contentListener.onStop();
            return Closure.RESULT_OK;
        }
        else
            // ExponentialReExpressClosure already tried to re-express, so quit.
            return Closure.RESULT_ERR;
    }  
      
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
        
    var contentObject = upcallInfo.contentObject;
    if (contentObject.content == null) {
        dump("NdnProtocol.ContentClosure: contentObject.content is null\n");
        return Closure.RESULT_ERR;
    }
    
    // If !this.uriEndsWithSegmentNumber, we use the segmentNumber to load multiple segments.
    // If this.uriEndsWithSegmentNumber, then we leave segmentNumber null.
    var segmentNumber = null;
    if (!this.uriEndsWithSegmentNumber && endsWithSegmentNumber(contentObject.name)) {
        segmentNumber = DataUtils.bigEndianToUnsignedInt
            (contentObject.name.components[contentObject.name.components.length - 1]);
        this.segmentStore.storeContent(segmentNumber, contentObject);
    }
    
    if ((segmentNumber == null || segmentNumber == 0) && !this.didOnStart) {
        // This is the first or only segment.
        /* TODO: Finish implementing check for META.
        var iMetaComponent = getIndexOfMetaComponent(contentObject.name);
        if (!this.uriEndsWithSegmentNumber && iMetaComponent >= 0 &&
            getIndexOfMetaComponent(this.uriName) < 0) {
            // The matched content name has a META component that wasn't requiested in the original
            //   URI.  Try to exclude the META component to get the "real" content.
            var nameWithoutMeta = new Name(contentObject.name.components.slice(0, iMetaComponent));
            var excludeMetaTemplate = this.segmentTemplate.clone();
            excludeMetaTemplate.exclude = new Exclude([MetaComponentPrefix, Exclude.ANY]);
            
            this.ndn.expressInterest
                (nameWithoutMeta, new ExponentialReExpressClosure(this), excludeMetaTemplate);
        }
        */
        
        this.didOnStart = true;
        
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
            ioService.newURI(contentUriSpec, this.aURI.originCharset, null));
    }

    if (segmentNumber == null) {
        // We are not doing segments, so just finish.
        this.contentListener.onReceivedContent(DataUtils.toString(contentObject.content));
        this.contentSha256.update(contentObject.content);
        this.contentListener.onStop();

        if (!this.uriEndsWithSegmentNumber) {
            var nameContentDigest = contentObject.name.getContentDigestValue();
            if (nameContentDigest != null &&
                !DataUtils.arraysEqual(nameContentDigest, this.contentSha256.finalize()))
                // TODO: How to show the user an error for invalid digest?
                dump("Content does not match digest in name " + contentObject.name.to_uri());
        }
        return Closure.RESULT_OK;
    }
    
    if (contentObject.signedInfo != null && contentObject.signedInfo.finalBlockID != null)
        this.finalSegmentNumber = DataUtils.bigEndianToUnsignedInt(contentObject.signedInfo.finalBlockID);

    // The content was already put in the store.  Retrieve as much as possible.
    var entry;
    while ((entry = this.segmentStore.maybeRetrieveNextEntry()) != null) {
        segmentNumber = entry.key;
        contentObject = entry.value;
        this.contentListener.onReceivedContent(DataUtils.toString(contentObject.content));
        this.contentSha256.update(contentObject.content);
        
        if (this.finalSegmentNumber != null && segmentNumber == this.finalSegmentNumber) {
            // Finished.
            this.contentListener.onStop();
            var nameContentDigest = contentObject.name.getContentDigestValue();
            if (nameContentDigest != null &&
                !DataUtils.arraysEqual(nameContentDigest, this.contentSha256.finalize()))
                // TODO: How to show the user an error for invalid digest?
                dump("Content does not match digest in name " + contentObject.name.to_uri());

            return Closure.RESULT_OK;
        }
    }

    if (this.finalSegmentNumber == null && !this.didRequestFinalSegment) {
        this.didRequestFinalSegment = true;
        // Try to determine the final segment now.
        var components = contentObject.name.components.slice
            (0, contentObject.name.components.length - 1);
            
        // Clone the template to set the childSelector.
        var childSelectorTemplate = this.segmentTemplate.clone();
        childSelectorTemplate.childSelector = 1;
        this.ndn.expressInterest
            (new Name(components), new ExponentialReExpressClosure(this), childSelectorTemplate);
    }

    // Request new segments.
    var toRequest = this.segmentStore.requestSegmentNumbers(2);
    for (var i = 0; i < toRequest.length; ++i) {
        if (this.finalSegmentNumber != null && toRequest[i] > this.finalSegmentNumber)
            continue;
        
        this.ndn.expressInterest
            (new Name(contentObject.name.components.slice
                      (0, contentObject.name.components.length - 1)).addSegment(toRequest[i]), 
             new ExponentialReExpressClosure(this), this.segmentTemplate);
    }
        
    return Closure.RESULT_OK;
  } catch (ex) {
        dump("ContentClosure.upcall exception: " + ex + "\n" + ex.stack);
        return Closure.RESULT_ERR;
  }
};

/*
 * A SegmentStore stores segments until they are retrieved in order starting with segment 0.
 */
var SegmentStore = function SegmentStore() {
    // Each entry is an object where the key is the segment number and value is null if
    //   the segment number is requested or the contentObject if received.
    this.store = new SortedArray();
    this.maxRetrievedSegmentNumber = -1;
};

SegmentStore.prototype.storeContent = function(segmentNumber, contentObject) {
    // We don't expect to try to store a segment that has already been retrieved, but check anyway.
    if (segmentNumber > this.maxRetrievedSegmentNumber)
        this.store.set(segmentNumber, contentObject);
};

/*
 * If the min segment number is this.maxRetrievedSegmentNumber + 1 and its value is not null, 
 *   then delete from the store, return the entry with key and value, and update maxRetrievedSegmentNumber.  
 * Otherwise return null.
 */
SegmentStore.prototype.maybeRetrieveNextEntry = function() {
    if (this.store.entries.length > 0 && this.store.entries[0].value != null &&
        this.store.entries[0].key == this.maxRetrievedSegmentNumber + 1) {
        var entry = this.store.entries[0];
        this.store.removeAt(0);
        ++this.maxRetrievedSegmentNumber;
        return entry;
    }
    else
        return null;
};

/*
 * Return an array of the next segment numbers that need to be requested so that the total
 *   requested segments is totalRequestedSegments.  If a segment store entry value is null, it is
 *   already requested and is not returned.  If a segment number is returned, create a
 *   entry in the segment store with a null value.
 */
SegmentStore.prototype.requestSegmentNumbers = function(totalRequestedSegments) {
    // First, count how many are already requested.
    var nRequestedSegments = 0;
    for (var i = 0; i < this.store.entries.length; ++i) {
        if (this.store.entries[i].value == null) {
            ++nRequestedSegments;
            if (nRequestedSegments >= totalRequestedSegments)
                // Already maxed out on requests.
                return [];
        }
    }
    
    var toRequest = [];
    var nextSegmentNumber = this.maxRetrievedSegmentNumber + 1;
    for (var i = 0; i < this.store.entries.length; ++i) {
        var entry = this.store.entries[i];
        // Fill in the gap before the segment number in the entry.
        while (nextSegmentNumber < entry.key) {
            toRequest.push(nextSegmentNumber);
            ++nextSegmentNumber;
            ++nRequestedSegments;
            if (nRequestedSegments >= totalRequestedSegments)
                break;
        }
        if (nRequestedSegments >= totalRequestedSegments)
            break;
        
        nextSegmentNumber = entry.key + 1;
    }
    
    // We already filled in the gaps for the segments in the store. Continue after the last.
    while (nRequestedSegments < totalRequestedSegments) {
        toRequest.push(nextSegmentNumber);
        ++nextSegmentNumber;
        ++nRequestedSegments;
    }
    
    // Mark the new segment numbers as requested.
    for (var i = 0; i < toRequest.length; ++i)
        this.store.set(toRequest[i], null);
    return toRequest;
}

/*
 * A SortedArray is an array of objects with key and value, where the key is an integer.
 */
var SortedArray = function SortedArray() {
    this.entries = [];
}

SortedArray.prototype.sortEntries = function() {
    this.entries.sort(function(a, b) { return a.key - b.key; });
};

SortedArray.prototype.indexOfKey = function(key) {
    for (var i = 0; i < this.entries.length; ++i) {
        if (this.entries[i].key == key)
            return i;
    }

    return -1;
}

SortedArray.prototype.set = function(key, value) {
    var i = this.indexOfKey(key);
    if (i >= 0) {
        this.entries[i].value = value;
        return;
    }
    
    this.entries.push({ key: key, value: value});
    this.sortEntries();
}

SortedArray.prototype.removeAt = function(index) {
    this.entries.splice(index, 1);
}

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
                else if (key == "ndn.MaxSuffixComponents" && nonNegativeInt >= 0)
                    template.maxSuffixComponents = nonNegativeInt;
                else if (key == "ndn.ChildSelector" && nonNegativeInt >= 0)
                    template.childSelector = nonNegativeInt;
                else if (key == "ndn.AnswerOriginKind" && nonNegativeInt >= 0)
                    template.answerOriginKind = nonNegativeInt;
                else if (key == "ndn.Scope" && nonNegativeInt >= 0)
                    template.scope = nonNegativeInt;
                else if (key == "ndn.InterestLifetime" && nonNegativeInt >= 0)
                    template.interestLifetime = nonNegativeInt;
                else if (key == "ndn.PublisherPublicKeyDigest")
                    template.publisherPublicKeyDigest = DataUtils.toNumbersFromString(unescape(value));
                else if (key == "ndn.Nonce")
                    template.nonce = DataUtils.toNumbersFromString(unescape(value));
                else if (key == "ndn.Exclude")
                    template.exclude = parseExclude(value);
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

/*
 * Parse the comma-separated list of exclude components and return an Exclude. 
 */
function parseExclude(value) {
    var excludeValues = [];
    
    var splitValue = value.split(',');
    for (var i = 0; i < splitValue.length; ++i) {
        var element = splitValue[i].trim();
        if (element == "*")
            excludeValues.push(Exclude.ANY)
        else
            excludeValues.push(Name.fromEscapedString(element));
    }

    return new Exclude(excludeValues);
}

/*
 * Return the index of the first compoment that starts with %C1.META, or -1 if not found.
 */
function getIndexOfMetaComponent(name) {
    for (var i = 0; i < name.components.length; ++i) {
        var component = name.components[i];
        if (component.length >= MetaComponentPrefix.length &&
            DataUtils.arraysEqual(component.subarray(0, MetaComponentPrefix.length), 
                                  MetaComponentPrefix))
            return i;
    }
    
    return -1;
}

var MetaComponentPrefix = new Uint8Array([0xc1, 0x2e, 0x4d, 0x45, 0x54, 0x41]);
