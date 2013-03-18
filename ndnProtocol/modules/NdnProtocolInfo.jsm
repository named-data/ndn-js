/*
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["NdnProtocolInfo"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");

var NdnProtocolInfo = function NdnProtocolInfo(){
};

NdnProtocolInfo.ndn = new NDN({ getTransport: function() { return new XpcomTransport(); },
                              verify: false });

// These are set once a connection is established.
NdnProtocolInfo.connectedNdnHubHost = null;
NdnProtocolInfo.connectedNdnHubPort = null;
NdnProtocolInfo.ndnHubChangedListenerList = [];

/*
 * When the NDN hub host or port is changed, the system calls listener(host, port).
 * If the current host and port are not null, call listener with the values to initialize.
 */
NdnProtocolInfo.addNdnHubChangedListener = function(listener) {
    NdnProtocolInfo.ndnHubChangedListenerList.push(listener);
    
    if (NdnProtocolInfo.connectedNdnHubHost != null && NdnProtocolInfo.connectedNdnHubPort != null) {
        try {
            listener(NdnProtocolInfo.connectedNdnHubHost, NdnProtocolInfo.connectedNdnHubPort);
        }
        catch (ex) {
            // Ignore error from the listener.
        }
    }
};

/*
 * If host and port are different than ndnHubHost or ndnHubPort, set them and call each
 * listener in ndnHubChangedListenerList.
 */
NdnProtocolInfo.setConnectedNdnHub = function(host, port) {
    if (host == NdnProtocolInfo.connectedNdnHubHost && port == NdnProtocolInfo.connectedNdnHubPort)
        // No change.
        return;
    
    NdnProtocolInfo.connectedNdnHubHost = host;
    NdnProtocolInfo.connectedNdnHubPort = port;
    for (var i = 0; i < NdnProtocolInfo.ndnHubChangedListenerList.length; ++i) {
        try {
            NdnProtocolInfo.ndnHubChangedListenerList[i](host, port);
        }
        catch (ex) {
            // Ignore error from the listener.
        }
    }
};

/*
 * Split the URI spec and return an object with protocol (including ':'), name, 
 *   search (including '?') and hash value (including '#').  
 * All result strings are trimmed.  This does not unescape the name.
 * The name may include a host and port.  
 */
NdnProtocolInfo.splitUri = function(spec) {
    spec = spec.trim();
    var result = {};
    var preHash = spec.split('#', 1)[0];
    result.hash = spec.substr(preHash.length).trim();
    var preSearch = preHash.split('?', 1)[0];
    result.search = preHash.substr(preSearch.length).trim();
    
    preSearch = preSearch.trim();
    var colonIndex = preSearch.indexOf(':');
    if (colonIndex >= 0) {
        result.protocol = preSearch.substr(0, colonIndex + 1).trim();
        result.name = preSearch.substr(colonIndex + 1).trim();    
    }
    else {
        result.protocol = "";
        result.name = preSearch;
    }
    
    return result;
};

/*
 * Do the work of the NDN Get Version buttons.
 * selector is "earliest", "latest", "previous" or "next".
 * currentWindow is the window with the address.
 * alertFunction(message) shows an alert.
 */
NdnProtocolInfo.getVersion = function(selector, currentWindow, alertFunction) {
 alertFunction("ndnGetVersion called");
 try {
  if (currentWindow._content.document.location.protocol != "ndn:") {
    alertFunction("The address must start with ndn:");
    return;
  }

  // Parse the same as in ndnProtocolService newChannel.
  var uriParts = NdnProtocolInfo.splitUri(currentWindow._content.document.location.href);
  var name = new Name(uriParts.name);
  var indexOfVersion = getIndexOfVersion(name);
  if (indexOfVersion < 0) {
    alertFunction("The ndn address does not have a version");
    return;
  }
  
  var escapedVersion = Name.toEscapedString(name.components[indexOfVersion]);

  var childSelector;
  if (selector == "earliest")
      childSelector = "ndn.ChildSelector=0";
  else if (selector == "latest")
      childSelector = "ndn.ChildSelector=1";
  else if (selector == "previous")
      childSelector = "ndn.ChildSelector=1&ndn.Exclude=" + escapedVersion + ",*";
  else if (selector == "next")
      childSelector = "ndn.ChildSelector=0&ndn.Exclude=*," + escapedVersion;
  else
      // Don't expect this to happen.
      return;

  var nameWithoutVersion = new Name(name.components.slice(0, indexOfVersion));
  var searchWithChildSelector = (uriParts.search == "" ? "?" : uriParts.search + "&") + childSelector;
    
  var uri = "ndn:" + nameWithoutVersion.to_uri() + searchWithChildSelector + uriParts.hash;
  currentWindow._content.document.location = uri;
 } catch (ex) {
       dump("ndnToolbarGetVersion exception: " + ex + "\n" + ex.stack);
 }
};

/*
 * Return the index of the last component that starts with 0xfd, or -1 if not found.
 */
function getIndexOfVersion(name) {
  for (var i = name.components.length - 1; i >= 0; --i) {
    if (name.components[i].length >= 1 && name.components[i][0] == 0xfd)
      return i;
  }

  return -1;
}
