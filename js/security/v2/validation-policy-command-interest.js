/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-command-interest.cpp
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
var Name = require('../../name.js').Name; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var CommandInterestSigner = require('../command-interest-signer.js').CommandInterestSigner; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var ValidationPolicy = require('./validation-policy.js').ValidationPolicy;

/**
 * ValidationPolicyCommandInterest extends ValidationPolicy as a policy for
 * stop-and-wait command Interests. See:
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 *
 * This policy checks the timestamp field of a stop-and-wait command Interest.
 * Signed Interest validation and Data validation requests are delegated to an
 * inner policy.
 *
 * Create a ValidationPolicyCommandInterest.
 * @param {ValidationPolicy} innerPolicy a ValidationPolicy for signed Interest
 * signature validation and Data validation. This must not be null.
 * @param {ValidationPolicyCommandInterest.Options} options (optional) The
 * stop-and-wait command Interest validation options. If omitted, use a default
 * Options().
 * @throws Error if innerPolicy is null.
 * @constructor
 */
var ValidationPolicyCommandInterest = function ValidationPolicyCommandInterest
  (innerPolicy, options)
{
  // Call the base constructor.
  ValidationPolicy.call(this);

  if (options == undefined)
    this.options_ = new ValidationPolicyCommandInterest.Options();
  else
    // Copy the Options.
    this.options_ = new ValidationPolicyCommandInterest.Options(options);

  this.container_ = []; // of ValidationPolicyCommandInterest.LastTimestampRecord
  this.nowOffsetMilliseconds_ = 0;

  if (innerPolicy == null)
    throw new Error("inner policy is missing");

  this.setInnerPolicy(innerPolicy);

  if (this.options_.gracePeriod_ < 0.0)
    this.options_.gracePeriod_ = 0.0;
};

ValidationPolicyCommandInterest.prototype = new ValidationPolicy();
ValidationPolicyCommandInterest.prototype.name = "ValidationPolicyCommandInterest";

exports.ValidationPolicyCommandInterest = ValidationPolicyCommandInterest;

/**
 * Create a ValidationPolicyCommandInterest.Options with the values.
 * @param {number|ValidationPolicyCommandInterest.Options} gracePeriodOrOptions
 * (optional) The tolerance of the initial timestamp in milliseconds. (However,
 * if this is another ValidationPolicyCommandInterest.Options, then copy values
 * from it.) If omitted, use a grace period of 2 minutes. A stop-and-wait
 * command Interest is considered "initial" if the validator has not recorded
 * the last timestamp from the same public key, or when such knowledge has been
 * erased. For an initial command Interest, its timestamp is compared to the
 * current system clock, and the command Interest is rejected if the absolute
 * difference is greater than the grace interval. The grace period should be
 * positive. Setting this option to 0 or negative causes the validator to
 * require exactly the same timestamp as the system clock, which most likely
 * rejects all command Interests.
 * @param {number} maxRecords (optional) The maximum number of distinct public
 * keys of which to record the last timestamp. If omitted, use 1000. The
 * validator records the last timestamps for every public key. For a subsequent
 * command Interest using the same public key, its timestamp is compared to the
 * last timestamp from that public key, and the command Interest is rejected if
 * its timestamp is less than or equal to the recorded timestamp.
 * This option limits the number of distinct public keys being tracked. If the
 * limit is exceeded, then the oldest record is deleted.
 * Setting max records to -1 allows tracking unlimited public keys. Setting max
 * records to 0 disables using last timestamp records and causes every command
 * Interest to be processed as initial.
 * @param {number} recordLifetime (optional) The maximum lifetime of a last
 * timestamp record in milliseconds. If omitted, use 1 hour. A last timestamp
 * record expires and can be deleted if it has not been refreshed within the
 * record lifetime. Setting the record lifetime to 0 or negative makes last
 * timestamp records expire immediately and causes every command Interest to be
 * processed as initial.
 * @constructor
 */
ValidationPolicyCommandInterest.Options = function ValidationPolicyCommandInterestOptions
  (gracePeriodOrOptions, maxRecords, recordLifetime)
{
  if (gracePeriodOrOptions instanceof ValidationPolicyCommandInterest.Options) {
    // The copy constructor.
    var options = gracePeriodOrOptions;

    this.gracePeriod_ = options.gracePeriod_;
    this.maxRecords_ = options.maxRecords_;
    this.recordLifetime_ = options.recordLifetime_;
  }
  else {
    var gracePeriod = gracePeriodOrOptions;

    if (gracePeriod == undefined)
      gracePeriod = 2 * 60 * 1000.0;
    if (maxRecords == undefined)
      maxRecords = 1000;
    if (recordLifetime == undefined)
      recordLifetime = 3600 * 1000.0;

    this.gracePeriod_ = gracePeriod;
    this.maxRecords_ = maxRecords;
    this.recordLifetime_ = recordLifetime;
  }
};

/**
 * @param {Data|Interest} dataOrInterest
 * @param {ValidationState} state
 * @param {function} continueValidation
 */
ValidationPolicyCommandInterest.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  if (dataOrInterest instanceof Data) {
    var data = dataOrInterest;
    this.getInnerPolicy().checkPolicy(data, state, continueValidation);
  }
  else {
    var interest = dataOrInterest;

    var keyName = [null];
    var timestamp = [0];
    if (!ValidationPolicyCommandInterest.parseCommandInterest_
        (interest, state, keyName, timestamp))
      return;

    if (!this.checkTimestamp_(state, keyName[0], timestamp[0]))
      return;

    this.getInnerPolicy().checkPolicy(interest, state, continueValidation);
  }
};

/**
 * Set the offset when insertNewRecord_() and cleanUp_() get the current time,
 * which should only be used for testing.
 * @param {number} nowOffsetMilliseconds The offset in milliseconds.
 */
ValidationPolicyCommandInterest.prototype.setNowOffsetMilliseconds_ = function
  (nowOffsetMilliseconds)
{
  this.nowOffsetMilliseconds_ = nowOffsetMilliseconds;
};

/**
 * @param {Name} keyName
 * @param {number} timestamp
 * @param {number} lastRefreshed
 * @constructor
 */
ValidationPolicyCommandInterest.LastTimestampRecord =
  function ValidationPolicyCommandInterestLastTimestampRecord
  (keyName, timestamp, lastRefreshed)
{
  // Copy the Name.
  this.keyName_ = new Name(keyName);
  this.timestamp_ = timestamp;
  this.lastRefreshed_ = lastRefreshed;
};

ValidationPolicyCommandInterest.prototype.cleanUp_ = function()
{
  // nowOffsetMilliseconds_ is only used for testing.
  var now = new Date().getTime() + this.nowOffsetMilliseconds_;
  var expiring = now - this.options_.recordLifetime_;

  while ((this.container_.length > 0 &&
           this.container_[0].lastRefreshed_ <= expiring) ||
         (this.options_.maxRecords_ >= 0 &&
           this.container_.length > this.options_.maxRecords_))
    this.container_.shift();
};

/**
 * Get the keyLocatorName and timestamp from the command interest.
 * @param {Interest} interest The Interest to parse.
 * @param {ValidationState} state On error, this calls state.fail and returns
 * false.
 * @param {Array<Name>} keyLocatorName Set keyLocatorName[0] to the KeyLocator
 * name.
 * @param {Array<number>} timestamp Set timestamp[0] to the timestamp as
 * milliseconds since Jan 1, 1970 UTC.
 * @return {boolean} On success, return true. On error, call state.fail and
 * return false.
 */
ValidationPolicyCommandInterest.parseCommandInterest_ = function
  (interest, state, keyLocatorName, timestamp)
{
  keyLocatorName[0] = new Name();
  timestamp[0] = 0;

  var name = interest.getName();
  if (name.size() < CommandInterestSigner.MINIMUM_SIZE) {
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "Command interest name `" + interest.getName().toUri() + "` is too short"));
    return false;
  }

  timestamp[0] = name.get(CommandInterestSigner.POS_TIMESTAMP).toNumber();

  keyLocatorName[0] = ValidationPolicy.getKeyLocatorName(interest, state);
  if (state.isOutcomeFailed())
    // Already failed.
    return false;

  return true;
};

/**
 * @param {ValidationState} state On error, this calls state.fail and returns
 * false.
 * @param {Name} keyName The key name.
 * @param {number} timestamp The timestamp as milliseconds since Jan 1, 1970 UTC.
 * @return {boolean} On success, return true. On error, call state.fail and
 * return false.
 */
ValidationPolicyCommandInterest.prototype.checkTimestamp_ = function
  (state, keyName, timestamp)
{
  this.cleanUp_();

  // nowOffsetMilliseconds_ is only used for testing.
  var now = new Date().getTime() + this.nowOffsetMilliseconds_;
  if (timestamp < now - this.options_.gracePeriod_ ||
      timestamp > now + this.options_.gracePeriod_) {
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "Timestamp is outside the grace period for key " + keyName.toUri()));
    return false;
  }

  var index = this.findByKeyName_(keyName);
  if (index >= 0) {
    if (timestamp <= this.container_[index].timestamp_) {
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "Timestamp is reordered for key " + keyName.toUri()));
      return false;
    }
  }

  var thisPolicy = this;
  state.addSuccessCallback
    (function(interest) {
      thisPolicy.insertNewRecord_(interest, keyName, timestamp);
    });

  return true;
};

/**
 * @param {Interest} interest
 * @param {Name} keyName
 * @param {number} timestamp
 */
ValidationPolicyCommandInterest.prototype.insertNewRecord_ = function
  (interest, keyName, timestamp)
{
  // nowOffsetMilliseconds_ is only used for testing.
  var now = new Date().getTime() + this.nowOffsetMilliseconds_;
  var newRecord = new ValidationPolicyCommandInterest.LastTimestampRecord
    (keyName, timestamp, now);

  var index = this.findByKeyName_(keyName);
  if (index >= 0)
    // Remove the existing record so we can move it to the end.
    this.container_.splice(index, 1);

  this.container_.push(newRecord);
};

/**
 * Find the record in container_ which has the keyName.
 * @param {Name} keyName The key name to search for.
 * @return {number} The index in container_ of the record, or -1 if not found.
 */
ValidationPolicyCommandInterest.prototype.findByKeyName_ = function(keyName)
{
  for (var i = 0; i < this.container_.length; ++i) {
    if (this.container_[i].keyName_.equals(keyName))
      return i;
  }

  return -1;
};
