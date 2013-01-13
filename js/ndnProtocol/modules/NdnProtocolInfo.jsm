/*
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["addNdnHubChangedListener", "setConnectedNdnHub", "splitUri"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

var ndnHubHost = null;
var ndnHubPort = null;
var ndnHubChangedListenerList = [];

/*
 * When the NDN hub host or port is changed, the system calls listener(host, port).
 * If the current host and port are not null, call listener with the values to initialize.
 */
function addNdnHubChangedListener(listener) {
    ndnHubChangedListenerList.push(listener);
    
    if (ndnHubHost != null && ndnHubPort != null) {
        try {
            listener(ndnHubHost, ndnHubPort);
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
function setConnectedNdnHub(host, port) {
    if (host == ndnHubHost && port == ndnHubPort)
        // No change.
        return;
    
    ndnHubHost = host;
    ndnHubPort = port;
    for (var i = 0; i < ndnHubChangedListenerList.length; ++i) {
        try {
            ndnHubChangedListenerList[i](host, port);
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
function splitUri(spec) {
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