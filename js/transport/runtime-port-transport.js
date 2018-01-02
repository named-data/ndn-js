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
 * A RuntimePortTransport extends Transport to connect to a WebExtensions
 * runtime.port.
 * @param {function} onReceivedObject (optional) If supplied and the received
 * object type field is not "Buffer" then just call this.onReceivedObject(obj).
 * If this is null, then don't call it.
 * @constructor
 */
var RuntimePortTransport = function RuntimePortTransport(onReceivedObject)
{
  // Call the base constructor.
  Transport.call(this);

  this.elementReader = null;
  this.connectionInfo = null; // Read by Face.
  this.onReceivedObject = onReceivedObject;
  this.port = null;
};

RuntimePortTransport.prototype = new Transport();
RuntimePortTransport.prototype.name = "RuntimePortTransport";

/**
 * Create a new RuntimePortTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold the runtime.port used to connect.
 * @param {runtime.port} port The runtime.port object.
 */
RuntimePortTransport.ConnectionInfo = function RuntimePortTransportConnectionInfo
  (port)
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);

  this.port = port;
};

RuntimePortTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
RuntimePortTransport.ConnectionInfo.prototype.name = "RuntimePortTransport.ConnectionInfo";

/**
 * Check if the fields of this RuntimePortTransport.ConnectionInfo equal the other
 * RuntimePortTransport.ConnectionInfo.
 * @param {RuntimePortTransport.ConnectionInfo} The other object to check.
 * @return {boolean} True if the objects have equal fields, false if not.
 */
RuntimePortTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null || other.port == undefined)
    return false;
  return this.port == other.port;
};

RuntimePortTransport.ConnectionInfo.prototype.toString = function()
{
  return "{}";
};

/**
 * Set the onReceivedObject callback, replacing any previous callback.
 * @param {function} onReceivedObject (optional) If supplied and the received
 * object type field is not "Buffer" then just call this.onReceivedObject(obj).
 * If this is null, then don't call it.
 */
RuntimePortTransport.prototype.setOnReceivedObject = function(onReceivedObject)
{
  this.onReceivedObject = onReceivedObject;
}

/**
 * Determine whether this transport connecting according to connectionInfo is to
 * a node on the current machine. RuntimePortTransport is always local.
 * @param {RuntimePortTransport.ConnectionInfo} connectionInfo This is ignored.
 * @param {function} onResult This calls onResult(true) because a runtime.port
 * is always local.
 * @param {function} onError This is ignored.
 */
RuntimePortTransport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  onResult(true);
};

/**
 * Connect to the runtime.port in connectionInfo. For a received object obj, if
 * obj.type is "Buffer", read an entire packet element from obj.data and call
 * elementListener.onReceivedElement(element). Otherwise just call
 * onReceivedObject(obj) using the callback given to the constructor.
 * @param {RuntimePortTransport.ConnectionInfo} connectionInfo The
 * ConnectionInfo with the runtime.port.
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onOpenCallback Once connected, call onOpenCallback().
 * @param {function} onClosedCallback (optional) If the connection is closed by
 * the remote host, call onClosedCallback(). If omitted or null, don't call it.
 */
RuntimePortTransport.prototype.connect = function
  (connectionInfo, elementListener, onOpenCallback, onClosedCallback)
{
  // The window listener is already set up.
  this.elementReader = new ElementReader(elementListener);
  this.connectionInfo = connectionInfo;
  this.port = this.connectionInfo.port;

  // Add a listener to wait for a message object from the tab
  var thisTransport = this;
  this.port.onMessage.addListener(function(obj) {
    if (obj.type == "Buffer")
      thisTransport.elementReader.onReceivedData
        (Buffer.isBuffer(obj.data) ? obj.data : new Buffer(obj.data));
    else {
      if (thisTransport.onReceivedObject != null)
        thisTransport.onReceivedObject(obj);
    }
  });

  this.port.onDisconnect.addListener(function() {
    thisTransport.port = null;
    if (onClosedCallback != null)
      onClosedCallback();
  });

  onOpenCallback();
};

/**
 * Send the JavaScript object over the connection created by connect.
 * @param {object} obj The object to send. If it is a JSON Buffer then it is
 * processed like an NDN packet.
 */
RuntimePortTransport.prototype.sendObject = function(obj)
{
  if (this.port == null) {
    console.log("RuntimePortTransport connection is not established.");
    return;
  }

  this.port.postMessage(obj);
};

/**
 * Send the buffer over the connection created by connect.
 * @param {Buffer} buffer The bytes to send.
 */
RuntimePortTransport.prototype.send = function(buffer)
{
  this.sendObject(buffer.toJSON());
};
