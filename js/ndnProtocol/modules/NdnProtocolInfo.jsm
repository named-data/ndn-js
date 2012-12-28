/*
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = ["addNdnHubChangedListener", "setConnectedNdnHub"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

var ndnHubHost = null;
var ndnHubPort = null;
var ndnHubChangedListenerList = [];

/*
 * When the NDN hub host or port is changed, the system calls listener(host, port).
 */
function addNdnHubChangedListener(listener) {
    ndnHubChangedListenerList.push(listener);
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