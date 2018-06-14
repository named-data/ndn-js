/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/command-interest-signer.cpp
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

/** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var SigningInfo = require('./signing-info.js').SigningInfo; /** @ignore */
var CommandInterestPreparer = require('./command-interest-preparer.js').CommandInterestPreparer;

/**
 * CommandInterestSigner is a helper class to create command interests. This
 * keeps track of a timestamp and generates command interests by adding name
 * components according to the NFD Signed Command Interests protocol.
 * See makeCommandInterest() for details.
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 *
 * Create a CommandInterestSigner to use the keyChain to sign.
 * @param {KeyChain} keyChain The KeyChain used to sign.
 * @constructor
 */
var CommandInterestSigner = function CommandInterestSigner(keyChain)
{
  // Call the base constructor.
  CommandInterestPreparer.call(this);

  this.keyChain_ = keyChain;
};

CommandInterestSigner.prototype = new CommandInterestPreparer();
CommandInterestSigner.prototype.name = "CommandInterestSigner";

exports.CommandInterestSigner = CommandInterestSigner;

CommandInterestSigner.POS_SIGNATURE_VALUE = -1;
CommandInterestSigner.POS_SIGNATURE_INFO =  -2;
CommandInterestSigner.POS_NONCE =           -3;
CommandInterestSigner.POS_TIMESTAMP =       -4;

CommandInterestSigner.MINIMUM_SIZE = 4;

/**
 * Append the timestamp and nonce name components to the supplied name, create
 * an Interest object and signs it with the KeyChain given to the constructor.
 * This ensures that the timestamp is greater than the timestamp used in the
 * previous call.
 * @param {Name} name The Name for the Interest, which is copied.
 * @param {SigningInfo} params (optional) The signing parameters. If omitted,
 * use a default SigningInfo().
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the SignatureInfo and to encode interest name for signing. If omitted, use
 * WireFormat getDefaultWireFormat().
 * @param {function} onComplete (optional) This calls onComplete(interest) with
 * the new command Interest object. (Some crypto libraries only use a callback,
 * so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {Interest} If onComplete is omitted, return the new command Interest
 * object. Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 */
CommandInterestSigner.prototype.makeCommandInterest = function
  (name, params, wireFormat, onComplete, onError)
{
  var arg2 = params;
  var arg3 = wireFormat;
  var arg4 = onComplete;
  var arg5 = onError;
  // arg2,       arg3,       arg4,       arg5
  // params,     wireFormat, onComplete, onError
  // params,     wireFormat, null,       null
  // params,     onComplete, onError,    null
  // params,     null,       null,       null
  // wireFormat, onComplete, onError,    null
  // wireFormat, null,       null,       null
  // onComplete, onError,    null,       null
  // null,       null,       null,       null
  if (arg2 instanceof SigningInfo)
    params = arg2;
  else
    params = undefined;

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else
    wireFormat = undefined;

  if (typeof arg2 === "function") {
    onComplete = arg2;
    onError = arg3;
  }
  else if (typeof arg3 === "function") {
    onComplete = arg3;
    onError = arg4;
  }
  else if (typeof arg4 === "function") {
    onComplete = arg4;
    onError = arg5;
  }
  else {
    onComplete = undefined;
    onError = undefined;
  }

  if (params == undefined)
    params = new SigningInfo();

  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();

  // This copies the Name.
  var commandInterest = new Interest(name);

  this.prepareCommandInterestName(commandInterest, wireFormat);
  return this.keyChain_.sign
    (commandInterest, params, wireFormat, onComplete, onError);
};
