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
}

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
}

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
}
