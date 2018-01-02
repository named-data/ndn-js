/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: Wentao Shang
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

/**
 * A MicroForwarderTransport extends Transport to connect to the browser's
 * micro forwarder service. This assumes that the MicroForwarder extensions has
 * been installed.
 * @constructor
 */
var MicroForwarderTransport = function MicroForwarderTransport()
{
  // Call the base constructor.
  Transport.call(this);

  this.elementReader = null;
  this.connectionInfo = null; // Read by Face.
  this.onReceivedObject = null;

  var thisTransport = this;
  window.addEventListener("message", function(event) {
    // We only accept messages from ourselves
    if (event.source != window)
      return;

    if (event.data.type && (event.data.type == "FromMicroForwarderStub")) {
      var obj = event.data.object;
      if (obj.type && obj.type == "Buffer") {
        if (thisTransport.elementReader != null)
          thisTransport.elementReader.onReceivedData(new Buffer(obj.data));
      }
      else {
        if (thisTransport.onReceivedObject)
          thisTransport.onReceivedObject(obj);
      }
    }
  }, false);
};

MicroForwarderTransport.prototype = new Transport();
MicroForwarderTransport.prototype.name = "MicroForwarderTransport";

/**
 * Create a new MicroForwarderTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold info for the micro forwarer connection.
 */
MicroForwarderTransport.ConnectionInfo = function MicroForwarderTransportConnectionInfo()
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);
};

MicroForwarderTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
MicroForwarderTransport.ConnectionInfo.prototype.name = "MicroForwarderTransport.ConnectionInfo";

/**
 * Check if the fields of this MicroForwarderTransport.ConnectionInfo equal the other
 * MicroForwarderTransport.ConnectionInfo.
 * @param {MicroForwarderTransport.ConnectionInfo} The other object to check.
 * @return {boolean} True if the objects have equal fields, false if not.
 */
MicroForwarderTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null)
    return false;
  return true;
};

MicroForwarderTransport.ConnectionInfo.prototype.toString = function()
{
  return "{}";
};

/**
 * Set the onReceivedObject callback, replacing any previous callback.
 * @param {function} onReceivedObject (optional) If supplied and the received
 * object type field is not "Buffer" then just call this.onReceivedObject(obj).
 * If this is null, then don't call it.
 */
MicroForwarderTransport.prototype.setOnReceivedObject = function(onReceivedObject)
{
  this.onReceivedObject = onReceivedObject;
}

/**
 * Determine whether this transport connecting according to connectionInfo is to
 * a node on the current machine. Unix transports are always local.
 * @param {MicroForwarderTransport.ConnectionInfo} connectionInfo This is ignored.
 * @param {function} onResult This calls onResult(true) because micro forwarder
 * transports are always local.
 * @param {function} onError This is ignored.
 */
MicroForwarderTransport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  onResult(true);
};

/**
 * Connect to the micro forwarder according to the info in connectionInfo.
 * Listen on the connection to read an entire packet element and call
 * elementListener.onReceivedElement(element). However, if the received object
 * type field is not "Buffer" then just call this.onReceivedObject(obj).
 * @param {MicroForwarderTransport.ConnectionInfo} connectionInfo
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {function} onclosedCallback (optional) If the connection is closed by
 * the remote host, call onclosedCallback(). If omitted or null, don't call it.
 */
MicroForwarderTransport.prototype.connect = function
  (connectionInfo, elementListener, onopenCallback, onclosedCallback)
{
  // The window listener is already set up.
  this.elementReader = new ElementReader(elementListener);
  this.connectionInfo = connectionInfo;
  onopenCallback();
};

/**
 * Send the JavaScript over the connection created by connect.
 * @param {object} obj The object to send. It should have a field "type". If
 * "type" is "Buffer" then it is processed like an NDN packet.
 */
MicroForwarderTransport.prototype.sendObject = function(obj)
{
  window.postMessage({
    type: "FromMicroForwarderTransport",
    object: obj
  }, "*");
};

/**
 * Send the buffer over the connection created by connect.
 * @param {Buffer} buffer The bytes to send.
 */
MicroForwarderTransport.prototype.send = function(buffer)
{
  if (this.connectionInfo == null) {
    console.log("MicroForwarderTransport connection is not established.");
    return;
  }

  this.sendObject(buffer.toJSON());
};
