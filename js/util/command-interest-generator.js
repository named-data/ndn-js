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

var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var CommandInterestPreparer = require('../security/command-interest-preparer.js').CommandInterestPreparer;

/**
 * A CommandInterestGenerator keeps track of a timestamp and generates command
 * interests according to the NFD Signed Command Interests protocol:
 * http://redmine.named-data.net/projects/nfd/wiki/Command_Interests
 *
 * Create a new CommandInterestGenerator and initialize the timestamp to now.
 * @constructor
 */
var CommandInterestGenerator = function CommandInterestGenerator()
{
  // Call the base constructor.
  CommandInterestPreparer.call(this);
};

CommandInterestGenerator.prototype = new CommandInterestPreparer();
CommandInterestGenerator.prototype.name = "CommandInterestGenerator";

exports.CommandInterestGenerator = CommandInterestGenerator;

/**
 * Append a timestamp component and a random value component to interest's name.
 * This ensures that the timestamp is greater than the timestamp used in the
 * previous call. Then use keyChain to sign the interest which appends a
 * SignatureInfo component and a component with the signature bits. If the
 * interest lifetime is not set, this sets it.
 * @param {Interest} interest The interest whose name is append with components.
 * @param {KeyChain} keyChain The KeyChain for calling sign.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the SignatureInfo and to encode interest name for signing. If omitted, use
 * WireFormat.getDefaultWireFormat().
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some crypto/database libraries only use a callback, so onComplete is
 * required to use these.)
 */
CommandInterestGenerator.prototype.generate = function
  (interest, keyChain, certificateName, wireFormat, onComplete)
{
  onComplete = (typeof wireFormat === "function") ? wireFormat : onComplete;
  wireFormat = (typeof wireFormat === "function" || !wireFormat) ?
    WireFormat.getDefaultWireFormat() : wireFormat;

  this.prepareCommandInterestName(interest, wireFormat);
  keyChain.sign(interest, certificateName, wireFormat, function() {
    if (interest.getInterestLifetimeMilliseconds() == null ||
        interest.getInterestLifetimeMilliseconds() < 0)
      // The caller has not set the interest lifetime, so set it here.
      interest.setInterestLifetimeMilliseconds(1000.0);

    if (onComplete)
      onComplete();
  });
};
