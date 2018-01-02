/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

/**
 * Transport is a base class for specific transport classes such as TcpTransport.
 * @constructor
 */
var Transport = function Transport()
{
};

exports.Transport = Transport;

/**
 * Transport.ConnectionInfo is a base class for connection information used by
 * subclasses of Transport.
 */
Transport.ConnectionInfo = function TransportConnectionInfo()
{
};

/**
 * Determine whether this transport connecting according to connectionInfo is to
 * a node on the current machine. This affects the processing of
 * Face.registerPrefix(): if the NFD is local, registration occurs with the
 * '/localhost/nfd...' prefix; if non-local, the library will attempt to use
 * remote prefix registration using '/localhop/nfd...'
 * @param {Transport.ConnectionInfo} connectionInfo A ConnectionInfo with the
 * host to check.
 * @param {function} onResult On success, this calls onResult(isLocal) where
 * isLocal is true if the host is local, false if not. We use callbacks because
 * this may need to do an asynchronous DNS lookup.
 * @param {function} onError On failure for DNS lookup or other error, this
 * calls onError(message) where message is an error string.
 */
Transport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  onError("Transport.isLocal is not implemented");
};
