/*
 * Copyright (C) 2013-2015 Regents of the University of California.
 * @author: Jeff Thompson
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var EXPORTED_SYMBOLS = ["NdnProtocolInfo"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");

var NdnProtocolInfo = function NdnProtocolInfo()
{
};

NdnProtocolInfo.face = new Face({ getTransport: function() { return new XpcomTransport(); },
                                verify: false });

// These are set once a connection is established.
NdnProtocolInfo.connectedNdnHubHost = null;
NdnProtocolInfo.connectedNdnHubPort = null;
NdnProtocolInfo.ndnHubChangedListenerList = [];

/*
 * When the NDN hub host or port is changed, the system calls listener(host, port).
 * If the current host and port are not null, call listener with the values to initialize.
 */
NdnProtocolInfo.addNdnHubChangedListener = function(listener)
{
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
NdnProtocolInfo.setConnectedNdnHub = function(host, port)
{
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
NdnProtocolInfo.splitUri = function(spec)
{
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
NdnProtocolInfo.getVersion = function(selector, currentWindow, alertFunction)
{
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
  }
  catch (ex) {
    dump("ndnToolbarGetVersion exception: " + ex + "\n" + ex.stack);
  }
};

/*
 * Return the index of the last component that starts with 0xfd, or -1 if not found.
 */
function getIndexOfVersion(name)
{
  for (var i = name.size() - 1; i >= 0; --i) {
    if (name.get(i).getValue().size() >= 1 && name.get(i).getValue().buf()[0] == 0xfd)
      return i;
  }

  return -1;
}

/*
 * Prompt the user and set the hub.  If the current address is ndn: then try to reload.
 * If changing the hub, then return a message to display such as "Hub: trying host:port",
 *   otherwise null for no message.
 * currentWindow is the window with the address.
 * alertFunction(message) shows an alert.
 */
NdnProtocolInfo.setHub = function(currentWindow, alertFunction)
{
  // Set the default port.
  var port = 6363;
  var hostAndPort = currentWindow.prompt
    ("Enter hub host:",
     NdnProtocolInfo.face.connectionInfo && NdnProtocolInfo.face.connectionInfo.host ?
       (NdnProtocolInfo.face.connectionInfo.host +
        (NdnProtocolInfo.face.connectionInfo.port != port ? ":" +
         NdnProtocolInfo.face.connectionInfo.port : ""))
       : "");
  if (!hostAndPort)
    return null;

  var splitHostAndPort = hostAndPort.split(':', 2);
  host = splitHostAndPort[0].trim();
  if (host == "")
    return null;

  if (splitHostAndPort.length >= 2) {
    port = parseInt(splitHostAndPort[1].trim());
    if (isNaN(port)) {
      alertFunction("Port must be a number: " + splitHostAndPort[1].trim());
      return null;
    }
  }

  if (NdnProtocolInfo.face.connectionInfo &&
      host == NdnProtocolInfo.face.connectionInfo.host &&
      port == NdnProtocolInfo.face.connectionInfo.port)
    // No change.
    return null;

  NdnProtocolInfo.face.createRoute(new XpcomTransport.ConnectionInfo(host, port));
  if (currentWindow._content.document.location.protocol == "ndn:")
    // Reload with the new hub.
    currentWindow._content.document.location = currentWindow._content.document.location.href;

  return "Hub: trying " + host + ":" + port;
};

/// The following is only used by Firefox for Android to set up the menus.
/// It really doesn't belong in this file, but it needs to be in a module that we know is
///   run on startup. If it can be put somewhere else without circular references, then it should be.

function loadIntoWindow(window)
{
  if (!window)
    return;

  // Add to Firefox for Android menu.
  window.NativeWindow.menu.add("NDN Get Version...", null, function() {
    ndnGetVersionClick(window);
  });
  window.NativeWindow.menu.add("NDN Hub...", null, function() {
    ndnHubClick(window);
  });
}

function ndnGetVersionClick(window)
{
  var alertFunction = function(message) { window.NativeWindow.toast.show(message, "short"); };

  var buttons = [
    {
      label: "Earliest",
      callback: function () {
        NdnProtocolInfo.getVersion("earliest", window, alertFunction);
      }
    },
    {
      label: "Prev.",
      callback: function () {
        NdnProtocolInfo.getVersion("previous", window, alertFunction);
      }
    },
    {
      label: "Next",
      callback: function () {
        NdnProtocolInfo.getVersion("next", window, alertFunction);
      }
    },
    {
      label: "Latest",
      callback: function () {
        NdnProtocolInfo.getVersion("latest", window, alertFunction);
      }
    }
  ];

  window.NativeWindow.doorhanger.show("NDN Get Version", "ndn-get-version", buttons,
     window.BrowserApp.selectedTab.id, { persistence: 1 });
}

function ndnHubClick(window)
{
  var alertFunction = function(message) { window.NativeWindow.toast.show(message, "short"); };

  var buttons = [
    {
      label: "Set...",
      callback: function () {
        var message = NdnProtocolInfo.setHub(window);
        if (message != null)
          androidHubMessage = message;
      }
    }
  ];

  window.NativeWindow.doorhanger.show(androidHubMessage, "ndn-hub", buttons,
     window.BrowserApp.selectedTab.id, { persistence: 1 });
}

var windowListener = {
  onOpenWindow: function(aWindow) {
    // Wait for the window to finish loading
    let domWindow = aWindow.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIDOMWindowInternal || Ci.nsIDOMWindow);
    domWindow.addEventListener("load", function() {
      domWindow.removeEventListener("load", arguments.callee, false);
      loadIntoWindow(domWindow);
    }, false);
  },

  onCloseWindow: function(aWindow) {},
  onWindowTitleChange: function(aWindow, aTitle) {}
};

function androidStartup(aData, aReason)
{
  let wm = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);

  // Load into any existing windows
  let windows = wm.getEnumerator("navigator:browser");
  while (windows.hasMoreElements()) {
    let domWindow = windows.getNext().QueryInterface(Ci.nsIDOMWindow);
    loadIntoWindow(domWindow);
  }

  // Load into any new windows
  wm.addListener(windowListener);
}

var androidHubMessage = "Hub: not connected";

function androidOnNdnHubChanged(host, port)
{
  androidHubMessage = "Hub: " + host + ":" + port;
}

// Do this here instead of using bootstrap.js since we don't want to set bootstrap true in install.rdf.
try {
  // startup() will only succeed on Android.
  androidStartup();
  NdnProtocolInfo.addNdnHubChangedListener(androidOnNdnHubChanged);
} catch (ex) {}
