/*
 * This is the ndn protocol handler.
 * Protocol handling code derived from http://mike.kaply.com/2011/01/18/writing-a-firefox-protocol-handler/
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

const nsIProtocolHandler = Ci.nsIProtocolHandler;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("chrome://modules/content/content-channel.jsm");
Components.utils.import("chrome://modules/content/ndn-protocol-info.jsm");

function NdnProtocol() {
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
                prefixUri = baseName.getPrefix(iFileName).toUri() + "/";
            uri.spec = "ndn:" + prefixUri + relativeName + uriParts.search + uriParts.hash;
        }

        return uri;
    },

    newChannel: function(aURI)
    {
        try {
            var uriParts = NdnProtocolInfo.splitUri(aURI.spec);

            var template = new Interest(new Name([]));
            // Use the same default as Face.expressInterest.
            template.setInterestLifetimeMilliseconds(4000);
            var searchWithoutNdn = extractNdnSearch(uriParts.search, template);

            var segmentTemplate = new Interest(new Name([]));
            // Only use the interest selectors which make sense for fetching further segments.
            segmentTemplate.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
            segmentTemplate.setScope(template.setScope());
            segmentTemplate.setInterestLifetimeMilliseconds(template.getInterestLifetimeMilliseconds());

            var requestContent = function(contentListener) {
                var name = new Name(uriParts.name);
                // Use the same Face object each time.
                var closure = new ContentClosure(NdnProtocolInfo.face, contentListener, name,
                     aURI, searchWithoutNdn + uriParts.hash, segmentTemplate);

                /* Disable until bug is fixed for opening multiple tabs.
                if (contentChannel.loadFlags & (1<<19))
                    // Load flags bit 19 means this channel is for the main window with the URL bar.
                    ContentClosure.setClosureForWindow(contentChannel.mostRecentWindow, closure);
                 */
                // TODO: Use expressInterest with callbacks, not Closure.
                NdnProtocolInfo.face.expressInterest
                    (name, new ExponentialReExpressClosure(closure), template);
            };

            var contentChannel = new ContentChannel(aURI, requestContent);
            return contentChannel;
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
 * TODO: Use expressInterest with callbacks, not Closure.
 */
var ContentClosure = function ContentClosure
      (face, contentListener, uriName, aURI, uriSearchAndHash, segmentTemplate)
{
    // Inherit from Closure.
    Closure.call(this);

    this.face = face;
    this.contentListener = contentListener;
    this.uriName = uriName;
    this.aURI = aURI;
    this.uriSearchAndHash = uriSearchAndHash;
    this.segmentTemplate = segmentTemplate;

    this.segmentStore = new SegmentStore();
    this.contentSha256 = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    this.contentSha256.init(this.contentSha256.SHA256);
    this.didRequestFinalSegment = false;
    this.finalSegmentNumber = null;
    this.didOnStart = false;
    this.uriEndsWithSegmentNumber = endsWithSegmentNumber(uriName);
    this.nameWithoutSegment = null;
    this.excludedMetaComponents = [];
    this.iMetaComponent = null;
};

ContentClosure.prototype.upcall = function(kind, upcallInfo)
{
  try {
    if (this.contentListener.isDone())
        // We are getting unexpected extra results.
        return Closure.RESULT_ERR;

    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
        dump("NdnProtocol: Interest timed out: " + upcallInfo.interest.toUri());
        if (!this.didOnStart) {
            // We have not received a segment to start the content yet, so assume the URI can't be fetched.
            this.contentListener.onStart("text/plain", "utf-8", this.aURI);
            this.contentListener.onReceivedContent
                ("The latest interest timed out after " + upcallInfo.interest.getInterestLifetimeMilliseconds() + " milliseconds.");
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

    var data = upcallInfo.data;
    if (data.getContent().isNull()) {
        dump("NdnProtocol.ContentClosure: data content is null\n");
        return Closure.RESULT_ERR;
    }

    // Assume this is only called once we're connected, report the host and port.
    NdnProtocolInfo.setConnectedNdnHub
      (this.face.connectionInfo.host, this.face.connectionInfo.port);

    // If !this.uriEndsWithSegmentNumber, we use the segmentNumber to load multiple segments.
    // If this.uriEndsWithSegmentNumber, then we leave segmentNumber null.
    var segmentNumber = null;
    if (!this.uriEndsWithSegmentNumber && endsWithSegmentNumber(data.getName()))
        segmentNumber = data.getName().get(-1).toSegment();

    if (!this.didOnStart) {
        // This is the first or only segment.
        var iMetaComponent = getIndexOfMetaComponent(data.getName());
        if (!this.uriEndsWithSegmentNumber && iMetaComponent >= 0 && getIndexOfMetaComponent(this.uriName) < 0) {
            // The matched content name has a META component that wasn't requested in the original
            //   URI.  Add this to the excluded META components to try to get the "real" content.
            var nameWithoutMeta = data.getName().getPrefix(iMetaComponent);
            if (this.excludedMetaComponents.length > 0 && iMetaComponent != this.iMetaComponent)
                // We are excluding META components at a new position in the name, so start over.
                this.excludedMetaComponents = [];
            this.iMetaComponent = iMetaComponent;
            this.excludedMetaComponents.push(data.getName().getComponent(iMetaComponent));
            // Exclude components are required to be sorted.
            this.excludedMetaComponents.sort(Exclude.compareComponents);

            var excludeMetaTemplate = this.segmentTemplate.clone();
            excludeMetaTemplate.setExclude(new Exclude(this.excludedMetaComponents));
            // TODO: Use expressInterest with callbacks, not Closure.
            this.face.expressInterest(nameWithoutMeta, new ExponentialReExpressClosure(this), excludeMetaTemplate);
            return Closure.RESULT_OK;
        }

        iNdnfsFileComponent = getIndexOfNdnfsFileComponent(data.getName());
        if (!this.uriEndsWithSegmentNumber && iNdnfsFileComponent >= 0 && getIndexOfNdnfsFileComponent(this.uriName) < 0) {
           // The matched content name has an NDNFS file meta component that wasn't requested in the original
           //   URI.  Expect the data.getName() to be /<prefix>/<file component>/<version>.
           // (We expect there to be a component after iNdnfsFileComponent but check anyway.)
           if (data.getName().size() >= iNdnfsFileComponent + 2) {
             // Make a name /<prefix>/<version>/%00.
             var nameWithoutMeta = data.getName().getPrefix(iNdnfsFileComponent).append
               (data.getName().get(iNdnfsFileComponent + 1)).appendSegment(0);
             // TODO: Use expressInterest with callbacks, not Closure.
             this.face.expressInterest(nameWithoutMeta, new ExponentialReExpressClosure(this), this.segmentTemplate);
           }
           return Closure.RESULT_OK;
        }

        this.didOnStart = true;

        // Get the URI from the Data including the version.
        var contentUriSpec;
        if (!this.uriEndsWithSegmentNumber && endsWithSegmentNumber(data.getName())) {
            var nameWithoutSegmentNumber = data.getName().getPrefix(-1);
            contentUriSpec = "ndn:" + nameWithoutSegmentNumber.toUri();
        }
        else
            contentUriSpec = "ndn:" + data.getName().toUri();

        // Include the search and hash.
        contentUriSpec += this.uriSearchAndHash;

        var contentTypeEtc = getNameContentTypeAndCharset(data.getName());
        var ioService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
        this.contentListener.onStart(contentTypeEtc.contentType, contentTypeEtc.contentCharset,
            ioService.newURI(contentUriSpec, this.aURI.originCharset, null));

        if (segmentNumber == null) {
            // We are not doing segments, so just finish.
            this.contentListener.onReceivedContent(DataUtils.toString(data.getContent().buf()));
            this.contentSha256.update(data.getContent().buf(), data.getContent().size());
            this.contentListener.onStop();
            ContentClosure.removeClosureForWindow(this);

            if (!this.uriEndsWithSegmentNumber) {
                var nameContentDigest = data.getName().getContentDigestValue();
                if (nameContentDigest != null && this.contentSha256 != null &&
                    !DataUtils.arraysEqual(nameContentDigest,
                              DataUtils.toNumbersFromString(this.contentSha256.finish(false))))
                    // TODO: How to show the user an error for invalid digest?
                    dump("Content does not match digest in name " + data.getName().toUri() + "\n");
            }
            return Closure.RESULT_OK;
        }
        else
            // We are doing segments.  Make sure we always request the same base name.
            this.nameWithoutSegment = data.getName().getPrefix(-1);
    }

    if (segmentNumber == null)
        // We should be doing segments at this point.
        return Closure.RESULT_ERR;

    if (!(data.getName().size() == this.nameWithoutSegment.size() + 1 &&
          this.nameWithoutSegment.match(data.getName())))
        // The data packet object name is not part of our sequence of segments.
        return Closure.RESULT_ERR;

    this.segmentStore.storeContent(segmentNumber, data);

    if (data.getMetaInfo() != null && data.getMetaInfo().getFinalBlockID().getValue().size() > 0)
        this.finalSegmentNumber = data.getMetaInfo().getFinalBlockID().toSegment();

    // The content was already put in the store.  Retrieve as much as possible.
    var entry;
    while ((entry = this.segmentStore.maybeRetrieveNextEntry()) != null) {
        segmentNumber = entry.key;
        data = entry.value;
        this.contentListener.onReceivedContent(DataUtils.toString(data.getContent().buf()));
        this.contentSha256.update(data.getContent().buf(), data.getContent().size());

        if (this.finalSegmentNumber != null && segmentNumber == this.finalSegmentNumber) {
            // Finished.
            this.contentListener.onStop();
            ContentClosure.removeClosureForWindow(this);
            var nameContentDigest = data.getName().getContentDigestValue();
            if (nameContentDigest != null && this.contentSha256 != null &&
                !DataUtils.arraysEqual(nameContentDigest,
                      DataUtils.toNumbersFromString(this.contentSha256.finish(false))))
                // TODO: How to show the user an error for invalid digest?
                dump("Content does not match digest in name " + data.getName().toUri() + "\n");

            return Closure.RESULT_OK;
        }
    }

    if (this.finalSegmentNumber == null && !this.didRequestFinalSegment) {
        this.didRequestFinalSegment = true;
        // Try to determine the final segment now.
        // Clone the template to set the childSelector.
        var childSelectorTemplate = this.segmentTemplate.clone();
        childSelectorTemplate.setChildSelector(1);
        // TODO: Use expressInterest with callbacks, not Closure.
        this.face.expressInterest
            (this.nameWithoutSegment, new ExponentialReExpressClosure(this), childSelectorTemplate);
    }

    // Request new segments.
    var toRequest = this.segmentStore.requestSegmentNumbers(2);
    for (var i = 0; i < toRequest.length; ++i) {
        if (this.finalSegmentNumber != null && toRequest[i] > this.finalSegmentNumber)
            continue;

        // TODO: Use expressInterest with callbacks, not Closure.
        this.face.expressInterest
            (new Name(this.nameWithoutSegment).addSegment(toRequest[i]),
             new ExponentialReExpressClosure(this), this.segmentTemplate);
    }

    return Closure.RESULT_OK;
  } catch (ex) {
        dump("ContentClosure.upcall exception: " + ex + "\n" + ex.stack);
        return Closure.RESULT_ERR;
  }
};

ContentClosure.closureForWindowList = [];

/*
 * We use closureForWindowList to keep only one closure for each document window.
 * window is the window with the URL bar.
 * closure is the ContentClosure to associate with it.
 * If there is already another closure for window, callits contentListener.onStop(); so
 *   that further calls to upcall will do nothing.
 */
ContentClosure.setClosureForWindow = function(window, closure)
{
    for (var i = 0; i < ContentClosure.closureForWindowList.length; ++i) {
        var entry = ContentClosure.closureForWindowList[i];
        if (entry.window == window) {
            try {
                entry.closure.contentListener.onStop();
            } catch (ex) {
                // Ignore any errors when stopping.
            }
            entry.closure = closure;
            return;
        }
    }

    ContentClosure.closureForWindowList.push({ window: window, closure: closure });
};

/*
 * Remove any entry in closureForWindowList for closure.  This is called when the closure is done.
 */
ContentClosure.removeClosureForWindow = function(closure)
{
    for (var i = ContentClosure.closureForWindowList.length - 1; i >= 0; --i) {
        if (ContentClosure.closureForWindowList[i].closure == closure)
            ContentClosure.closureForWindowList.splice(i, 1);
    }
};

/*
 * A SegmentStore stores segments until they are retrieved in order starting with segment 0.
 */
var SegmentStore = function SegmentStore()
{
    // Each entry is an object where the key is the segment number and value is null if
    //   the segment number is requested or the data if received.
    this.store = new SortedArray();
    this.maxRetrievedSegmentNumber = -1;
};

SegmentStore.prototype.storeContent = function(segmentNumber, data)
{
    // We don't expect to try to store a segment that has already been retrieved, but check anyway.
    if (segmentNumber > this.maxRetrievedSegmentNumber)
        this.store.set(segmentNumber, data);
};

/*
 * If the min segment number is this.maxRetrievedSegmentNumber + 1 and its value is not null,
 *   then delete from the store, return the entry with key and value, and update maxRetrievedSegmentNumber.
 * Otherwise return null.
 */
SegmentStore.prototype.maybeRetrieveNextEntry = function()
{
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
SegmentStore.prototype.requestSegmentNumbers = function(totalRequestedSegments)
{
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
};

/*
 * A SortedArray is an array of objects with key and value, where the key is an integer.
 */
var SortedArray = function SortedArray()
{
    this.entries = [];
};

SortedArray.prototype.sortEntries = function()
{
    this.entries.sort(function(a, b) { return a.key - b.key; });
};

SortedArray.prototype.indexOfKey = function(key)
{
    for (var i = 0; i < this.entries.length; ++i) {
        if (this.entries[i].key == key)
            return i;
    }

    return -1;
};

SortedArray.prototype.set = function(key, value)
{
    var i = this.indexOfKey(key);
    if (i >= 0) {
        this.entries[i].value = value;
        return;
    }

    this.entries.push({ key: key, value: value});
    this.sortEntries();
};

SortedArray.prototype.removeAt = function(index)
{
    this.entries.splice(index, 1);
};

/*
 * Scan the name from the last component to the first (skipping special name components)
 *   for a recognized file name extension, and return an object with properties contentType and charset.
 */
function getNameContentTypeAndCharset(name)
{
    var iFileName = name.indexOfFileName();
    if (iFileName < 0)
        // Get the default mime type.
        return MimeTypes.getContentTypeAndCharset("");

    return MimeTypes.getContentTypeAndCharset
        (DataUtils.toString(name.get(iFileName).getValue().buf()).toLowerCase());
}

/*
 * Return true if the last component in the name is a segment number.  Require at least one name component
 * before the segment number.
 */
function endsWithSegmentNumber(name)
{
    return name.size() >= 2 &&
        name.get(-1).getValue().size() >= 1 &&
        name.get(-1).getValue().buf()[0] == 0;
}

/*
 * Find all search keys starting with "ndn." and set the attribute in template.
 * Return the search string including the starting "?" but with the "ndn." keys removed,
 *   or return "" if there are no search terms left.
 */
function extractNdnSearch(search, template)
{
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
                    template.setMinSuffixComponents(nonNegativeInt);
                else if (key == "ndn.MaxSuffixComponents" && nonNegativeInt >= 0)
                    template.setMaxSuffixComponents(nonNegativeInt);
                else if (key == "ndn.ChildSelector" && nonNegativeInt >= 0)
                    template.setChildSelector(nonNegativeInt);
                else if (key == "ndn.AnswerOriginKind" && nonNegativeInt >= 0)
                    template.setAnswerOriginKind(nonNegativeInt);
                else if (key == "ndn.Scope" && nonNegativeInt >= 0)
                    template.setScope(nonNegativeInt);
                else if (key == "ndn.InterestLifetime" && nonNegativeInt >= 0)
                    template.setInterestLifetimeMilliseconds(nonNegativeInt);
                else if (key == "ndn.PublisherPublicKeyDigest")
                    template.publisherPublicKeyDigest = DataUtils.toNumbersFromString(unescape(value));
                else if (key == "ndn.Nonce")
                    template.setNonce(DataUtils.toNumbersFromString(unescape(value)));
                else if (key == "ndn.Exclude")
                    template.setExclude(parseExclude(value));
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
function parseExclude(value)
{
    var excludeValues = [];

    var splitValue = value.split(',');
    for (var i = 0; i < splitValue.length; ++i) {
        var element = splitValue[i].trim();
        if (element == "*")
            excludeValues.push(Exclude.ANY);
        else
            excludeValues.push(Name.fromEscapedString(element));
    }

    return new Exclude(excludeValues);
}

/**
 * Get the index of the first component that starts with %C1.META.
 * @param {Name} name The Name to search.
 * @returns {number} The index or -1 if not found.
 */
function getIndexOfMetaComponent(name)
{
  for (var i = 0; i < name.size(); ++i) {
    var component = name.get(i).getValue().buf();
    if (component.length >= MetaComponentPrefix.length &&
      DataUtils.arraysEqual(component.slice(0, MetaComponentPrefix.length), MetaComponentPrefix))
        return i;
  }

  return -1;
}

var MetaComponentPrefix = new Buffer([0xc1, 0x2e, 0x4d, 0x45, 0x54, 0x41]);

/**
 * Get the index of the first component that is the NDNFS file meta data marker.
 * @param {type} name The Name to search.
 * @returns {number} The index or -1 if not found.
 */
function getIndexOfNdnfsFileComponent(name)
{
  for (var i = 0; i < name.size(); ++i) {
    if (name.get(i).getValue().equals(NdnfsFileComponent))
      return i;
  }

  return -1;
}

var NdnfsFileComponent = Name.fromEscapedString("%C1.FS.file");

