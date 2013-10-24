/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

// The NDN constructor uses TcpTransport by default which is not available in the browser, so override to WebSocketTransport.
exports.TcpTransport = ndn.WebSocketTransport;
