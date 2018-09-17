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

/** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var InterestFilter = require('../interest-filter.js').InterestFilter; /** @ignore */
var ForwardingFlags = require('../forwarding-flags.js').ForwardingFlags; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * A MemoryContentCache holds a set of Data packets and answers an Interest to
 * return the correct Data packet. The cache is periodically cleaned up to
 * remove each stale Data packet based on its FreshnessPeriod (if it has one).
 * @note This class is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
 *
 * Create a new MemoryContentCache to use the given Face.
 *
 * @param {Face} face The Face to use to call registerPrefix and
 * setInterestFilter, and which will call this object's OnInterest callback.
 * @param {number} cleanupIntervalMilliseconds (optional) The interval
 * in milliseconds between each check to clean up stale content in the cache. If
 * omitted, use a default of 1000 milliseconds. If this is a large number, then
 * effectively the stale content will not be removed from the cache.
 * @constructor
 */
var MemoryContentCache = function MemoryContentCache
  (face, cleanupIntervalMilliseconds)
{
  cleanupIntervalMilliseconds = (cleanupIntervalMilliseconds || 1000.0);

  this.face = face;
  this.cleanupIntervalMilliseconds = cleanupIntervalMilliseconds;
  this.nextCleanupTime = new Date().getTime() + cleanupIntervalMilliseconds;

  this.onDataNotFoundForPrefix = {}; /**< The map key is the prefix.toUri().
                                          The value is an OnInterest function. */
  this.interestFilterIdList = []; /**< elements are number */
  this.registeredPrefixIdList = []; /**< elements are number */
  this.noStaleTimeCache = []; /**< elements are MemoryContentCache.Content */
  this.staleTimeCache = [];   /**< elements are MemoryContentCache.StaleTimeContent */
  //StaleTimeContent.Compare contentCompare_;
  this.emptyComponent = new Name.Component();
  this.pendingInterestTable = [];
  this.minimumCacheLifetime_ = 0.0;

  var thisMemoryContentCache = this;
  this.storePendingInterestCallback = function
    (localPrefix, localInterest, localFace, localInterestFilterId, localFilter) {
       thisMemoryContentCache.storePendingInterest(localInterest, localFace);
    };
};

exports.MemoryContentCache = MemoryContentCache;

/**
 * Call registerPrefix on the Face given to the constructor so that this
 * MemoryContentCache will answer interests whose name has the prefix.
 * Alternatively, if the Face's registerPrefix has already been called,
 * then you can call this object's setInterestFilter.
 * @param {Name} prefix The Name for the prefix to register. This copies the Name.
 * @param {function} onRegisterFailed If this fails to register the prefix for
 * any reason, this calls onRegisterFailed(prefix) where prefix is the prefix
 * given to registerPrefix.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onRegisterSuccess (optional) When this receives a success
 * message, this calls onRegisterSuccess[0](prefix, registeredPrefixId). If
 * onRegisterSuccess is [null] or omitted, this does not use it. (As a special
 * case, this optional parameter is supplied as an array of one function,
 * instead of just a function, in order to detect when it is used instead of the
 * following optional onDataNotFound function.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onDataNotFound (optional) If a data packet for an interest
 * is not found in the cache, this forwards the interest by calling
 * onDataNotFound(prefix, interest, face, interestFilterId, filter). Your
 * callback can find the Data packet for the interest and call
 * face.putData(data). If your callback cannot find the Data packet, it can
 * optionally call storePendingInterest(interest, face) to store the pending
 * interest in this object to be satisfied by a later call to add(data). If you
 * want to automatically store all pending interests, you can simply use
 * getStorePendingInterest() for onDataNotFound. If onDataNotFound is omitted or
 * null, this does not use it.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {ForwardingFlags} flags (optional) See Face.registerPrefix.
 * @param {WireFormat} wireFormat (optional) See Face.registerPrefix.
 */
MemoryContentCache.prototype.registerPrefix = function
  (prefix, onRegisterFailed, onRegisterSuccess, onDataNotFound, flags, wireFormat)
{
  var arg3 = onRegisterSuccess;
  var arg4 = onDataNotFound;
  var arg5 = flags;
  var arg6 = wireFormat;
  // arg3,                arg4,            arg5,            arg6 may be:
  // [OnRegisterSuccess], OnDataNotFound,  ForwardingFlags, WireFormat
  // [OnRegisterSuccess], OnDataNotFound,  ForwardingFlags, null
  // [OnRegisterSuccess], OnDataNotFound,  WireFormat,      null
  // [OnRegisterSuccess], OnDataNotFound,  null,            null
  // [OnRegisterSuccess], ForwardingFlags, WireFormat,      null
  // [OnRegisterSuccess], ForwardingFlags, null,            null
  // [OnRegisterSuccess], WireFormat,      null,            null
  // [OnRegisterSuccess], null,            null,            null
  // OnDataNotFound,      ForwardingFlags, WireFormat,      null
  // OnDataNotFound,      ForwardingFlags, null,            null
  // OnDataNotFound,      WireFormat,      null,            null
  // OnDataNotFound,      null,            null,            null
  // ForwardingFlags,     WireFormat,      null,            null
  // ForwardingFlags,     null,            null,            null
  // WireFormat,          null,            null,            null
  // null,                null,            null,            null
  if (typeof arg3 === "object" && arg3.length === 1 &&
      typeof arg3[0] === "function")
    onRegisterSuccess = arg3[0];
  else
    onRegisterSuccess = null;

  if (typeof arg3 === "function")
    onDataNotFound = arg3;
  else if (typeof arg4 === "function")
    onDataNotFound = arg4;
  else
    onDataNotFound = null;

  if (arg3 instanceof ForwardingFlags)
    flags = arg3;
  else if (arg4 instanceof ForwardingFlags)
    flags = arg4;
  else if (arg5 instanceof ForwardingFlags)
    flags = arg5;
  else
    flags = new ForwardingFlags();

  if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else if (arg4 instanceof WireFormat)
    wireFormat = arg4;
  else if (arg5 instanceof WireFormat)
    wireFormat = arg5;
  else if (arg6 instanceof WireFormat)
    wireFormat = arg6;
  else
    wireFormat = WireFormat.getDefaultWireFormat();

  if (onDataNotFound)
    this.onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound;
  var registeredPrefixId = this.face.registerPrefix
    (prefix, this.onInterest.bind(this), onRegisterFailed, onRegisterSuccess,
     flags, wireFormat);
  this.registeredPrefixIdList.push(registeredPrefixId);
};

/**
 * Call setInterestFilter on the Face given to the constructor so that this
 * MemoryContentCache will answer interests whose name matches the filter.
 * There are two forms of setInterestFilter.
 * The first form uses the exact given InterestFilter:
 * setInterestFilter(filter, [onDataNotFound]).
 * The second form creates an InterestFilter from the given prefix Name:
 * setInterestFilter(prefix, [onDataNotFound]).
 * @param {InterestFilter} filter The InterestFilter with a prefix and optional
 * regex filter used to match the name of an incoming Interest. This makes a
 * copy of filter.
 * @param {Name} prefix The Name prefix used to match the name of an incoming
 * Interest.
 * @param {function} onDataNotFound (optional) If a data packet for an interest
 * is not found in the cache, this forwards the interest by calling
 * onDataNotFound(prefix, interest, face, interestFilterId, filter). Your
 * callback can find the Data packet for the interest and call
 * face.putData(data). If your callback cannot find the Data packet, it can
 * optionally call storePendingInterest(interest, face) to store the pending
 * interest in this object to be satisfied by a later call to add(data). If you
 * want to automatically store all pending interests, you can simply use
 * getStorePendingInterest() for onDataNotFound. If onDataNotFound is omitted or
 * null, this does not use it.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
MemoryContentCache.prototype.setInterestFilter = function
  (filterOrPrefix, onDataNotFound)
{
  if (onDataNotFound) {
    var prefix;
    if (typeof filterOrPrefix === 'object' && filterOrPrefix instanceof InterestFilter)
      prefix = filterOrPrefix.getPrefix();
    else
      prefix = filterOrPrefix;
    this.onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound;
  }
  var interestFilterId = this.face.setInterestFilter
    (filterOrPrefix, this.onInterest.bind(this));
  this.interestFilterIdList.push(interestFilterId);
};

/**
 * Call Face.unsetInterestFilter and Face.removeRegisteredPrefix for all the
 * prefixes given to the setInterestFilter and registerPrefix method on this
 * MemoryContentCache object so that it will not receive interests any more. You
 * can call this if you want to "shut down" this MemoryContentCache while your
 * application is still running.
 */
MemoryContentCache.prototype.unregisterAll = function()
{
  for (var i = 0; i < this.interestFilterIdList.length; ++i)
    this.face.unsetInterestFilter(this.interestFilterIdList[i]);
  this.interestFilterIdList = [];

  for (var i = 0; i < this.registeredPrefixIdList.length; ++i)
    this.face.removeRegisteredPrefix(this.registeredPrefixIdList[i]);
  this.registeredPrefixIdList = [];

  // Also clear each onDataNotFoundForPrefix given to registerPrefix.
  this.onDataNotFoundForPrefix = {};
};

/**
 * Add the Data packet to the cache so that it is available to use to
 * answer interests. If data.getMetaInfo().getFreshnessPeriod() is not
 * negative, set the staleness time to now plus the maximum of
 * data.getMetaInfo().getFreshnessPeriod() and minimumCacheLifetime, which is
 * checked during cleanup to remove stale content.
 * This also checks if cleanupIntervalMilliseconds
 * milliseconds have passed and removes stale
 * content from the cache. After removing stale content, remove timed-out
 * pending interests from storePendingInterest(), then if the added Data packet
 * satisfies any interest, send it through the face and remove the interest
 * from the pending interest table.
 * @param {Data} data The Data packet object to put in the cache. This copies
 * the fields from the object.
 */
MemoryContentCache.prototype.add = function(data)
{
  var nowMilliseconds = new Date().getTime();
  this.doCleanup(nowMilliseconds);

  if (data.getMetaInfo().getFreshnessPeriod() != null &&
      data.getMetaInfo().getFreshnessPeriod() >= 0.0) {
    // The content will go stale, so use staleTimeCache.
    var content = new MemoryContentCache.StaleTimeContent
      (data, nowMilliseconds, this.minimumCacheLifetime_);
    // Insert into staleTimeCache, sorted on content.cacheRemovalTimeMilliseconds_.
    // Search from the back since we expect it to go there.
    var i = this.staleTimeCache.length - 1;
    while (i >= 0) {
      if (this.staleTimeCache[i].cacheRemovalTimeMilliseconds_ <=
          content.cacheRemovalTimeMilliseconds_)
        break;
      --i;
    }
    // Element i is the greatest less than or equal to
    // content.cacheRemovalTimeMilliseconds_, so insert after it.
    this.staleTimeCache.splice(i + 1, 0, content);
  }
  else
    // The data does not go stale, so use noStaleTimeCache.
    this.noStaleTimeCache.push(new MemoryContentCache.Content(data));

  // Remove timed-out interests and check if the data packet matches any pending
  // interest.
  // Go backwards through the list so we can erase entries.
  for (var i = this.pendingInterestTable.length - 1; i >= 0; --i) {
    if (this.pendingInterestTable[i].isTimedOut(nowMilliseconds)) {
      this.pendingInterestTable.splice(i, 1);
      continue;
    }
    if (this.pendingInterestTable[i].getInterest().matchesName(data.getName())) {
      try {
        // Send to the same face from the original call to onInterest.
        // wireEncode returns the cached encoding if available.
        this.pendingInterestTable[i].getFace().send(data.wireEncode().buf());
      }
      catch (ex) {
        if (LOG > 0)
          console.log("" + ex);
        return;
      }

      // The pending interest is satisfied, so remove it.
      this.pendingInterestTable.splice(i, 1);
    }
  }
};

/**
 * Store an interest from an OnInterest callback in the internal pending
 * interest table (normally because there is no Data packet available yet to
 * satisfy the interest). add(data) will check if the added Data packet
 * satisfies any pending interest and send it through the face.
 * @param {Interest} interest The Interest for which we don't have a Data packet
 * yet. You should not modify the interest after calling this.
 * @param {Face} face The Face with the connection which received
 * the interest. This comes from the OnInterest callback.
 */
MemoryContentCache.prototype.storePendingInterest = function(interest, face)
{
  this.pendingInterestTable.push
    (new MemoryContentCache.PendingInterest(interest, face));
};

/**
 * Return a callback to use for onDataNotFound in registerPrefix which simply
 * calls storePendingInterest() to store the interest that doesn't match a
 * Data packet. add(data) will check if the added Data packet satisfies any
 * pending interest and send it.
 * @return {function} A callback to use for onDataNotFound in registerPrefix().
 */
MemoryContentCache.prototype.getStorePendingInterest = function()
{
  return this.storePendingInterestCallback;
};

/**
 * Get the minimum lifetime before removing stale content from the cache.
 * @return {number} The minimum cache lifetime in milliseconds.
 */
MemoryContentCache.prototype.getMinimumCacheLifetime = function()
{
  return this.minimumCacheLifetime_;
};

/**
 * Set the minimum lifetime before removing stale content from the cache which
 * can keep content in the cache longer than the lifetime defined in the meta
 * info. This can be useful for matching interests where MustBeFresh is false.
 * The default minimum cache lifetime is zero, meaning that content is removed
 * when its lifetime expires.
 * @param {number} minimumCacheLifetime The minimum cache lifetime in
 * milliseconds.
 */
MemoryContentCache.prototype.setMinimumCacheLifetime = function
  (minimumCacheLifetime)
{
  this.minimumCacheLifetime_ = minimumCacheLifetime;
};

/**
 * This is the OnInterest callback which is called when the library receives
 * an interest whose name has the prefix given to registerPrefix. First check
 * if cleanupIntervalMilliseconds milliseconds have passed and remove stale
 * content from the cache. Then search the cache for the Data packet, matching
 * any interest selectors including ChildSelector, and send the Data packet
 * to the face. If no matching Data packet is in the cache, call
 * the callback in onDataNotFoundForPrefix (if defined).
 */
MemoryContentCache.prototype.onInterest = function
  (prefix, interest, face, interestFilterId, filter)
{
  var nowMilliseconds = new Date().getTime();
  this.doCleanup(nowMilliseconds);

  var selectedComponent = null;
  var selectedEncoding = null;
  // We need to iterate over both arrays.
  var totalSize = this.staleTimeCache.length + this.noStaleTimeCache.length;
  for (var i = 0; i < totalSize; ++i) {
    var content;
    var isFresh = true;
    if (i < this.staleTimeCache.length) {
      content = this.staleTimeCache[i];
      isFresh = content.isFresh(nowMilliseconds);
    }
    else
      // We have iterated over the first array. Get from the second.
      content = this.noStaleTimeCache[i - this.staleTimeCache.length];

    if (interest.matchesName(content.getName()) &&
        !(interest.getMustBeFresh() && !isFresh)) {
      if (interest.getChildSelector() == null) {
        // No child selector, so send the first match that we have found.
        face.send(content.getDataEncoding());
        return;
      }
      else {
        // Update selectedEncoding based on the child selector.
        var component;
        if (content.getName().size() > interest.getName().size())
          component = content.getName().get(interest.getName().size());
        else
          component = this.emptyComponent;

        var gotBetterMatch = false;
        if (selectedEncoding === null)
          // Save the first match.
          gotBetterMatch = true;
        else {
          if (interest.getChildSelector() == 0) {
            // Leftmost child.
            if (component.compare(selectedComponent) < 0)
              gotBetterMatch = true;
          }
          else {
            // Rightmost child.
            if (component.compare(selectedComponent) > 0)
              gotBetterMatch = true;
          }
        }

        if (gotBetterMatch) {
          selectedComponent = component;
          selectedEncoding = content.getDataEncoding();
        }
      }
    }
  }

  if (selectedEncoding !== null)
    // We found the leftmost or rightmost child.
    face.send(selectedEncoding);
  else {
    // Call the onDataNotFound callback (if defined).
    var onDataNotFound = this.onDataNotFoundForPrefix[prefix.toUri()];
    if (onDataNotFound)
      onDataNotFound(prefix, interest, face, interestFilterId, filter);
  }
};

/**
 * Check if now is greater than nextCleanupTime and, if so, remove stale
 * content from staleTimeCache and reset nextCleanupTime based on
 * cleanupIntervalMilliseconds. Since add(Data) does a sorted insert into
 * staleTimeCache, the check for stale data is quick and does not require
 * searching the entire staleTimeCache.
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 */
MemoryContentCache.prototype.doCleanup = function(nowMilliseconds)
{
  if (nowMilliseconds >= this.nextCleanupTime) {
    // staleTimeCache is sorted on cacheRemovalTimeMilliseconds_, so we only need to
    // erase the stale entries at the front, then quit.
    while (this.staleTimeCache.length > 0 &&
           this.staleTimeCache[0].isPastRemovalTime(nowMilliseconds))
      this.staleTimeCache.shift();

    this.nextCleanupTime = nowMilliseconds + this.cleanupIntervalMilliseconds;
  }
};

/**
 * Content is a private class to hold the name and encoding for each entry
 * in the cache. This base class is for a Data packet without a FreshnessPeriod.
 *
 * Create a new Content entry to hold data's name and wire encoding.
 * @param {Data} data The Data packet whose name and wire encoding are copied.
 */
MemoryContentCache.Content = function MemoryContentCacheContent(data)
{
  // Allow an undefined data so that StaleTimeContent can set the prototype.
  if (data) {
    // Copy the name.
    this.name = new Name(data.getName());
    // wireEncode returns the cached encoding if available.
    this.dataEncoding = data.wireEncode().buf();
  }
};

MemoryContentCache.Content.prototype.getName = function() { return this.name; };

MemoryContentCache.Content.prototype.getDataEncoding = function() { return this.dataEncoding; };

/**
 * StaleTimeContent extends Content to include the cacheRemovalTimeMilliseconds_ for
 * when this entry should be cleaned up from the cache.
 *
 * Create a new StaleTimeContent to hold data's name and wire encoding
 * as well as the cacheRemovalTimeMilliseconds_ which is now plus the maximum of
 * data.getMetaInfo().getFreshnessPeriod() and the minimumCacheLifetime.
 * @param {Data} data The Data packet whose name and wire encoding are copied.
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 * @param {number} minimumCacheLifetime The minimum cache lifetime in milliseconds.
 */
MemoryContentCache.StaleTimeContent = function MemoryContentCacheStaleTimeContent
  (data, nowMilliseconds, minimumCacheLifetime)
{
  // Call the base constructor.
  MemoryContentCache.Content.call(this, data);

  // Set up cacheRemovalTimeMilliseconds_ which is the time when the content
  // becomes stale and should be removed from the cache in milliseconds
  // according to new Date().getTime().
  this.cacheRemovalTimeMilliseconds_ = nowMilliseconds +
    Math.max(data.getMetaInfo().getFreshnessPeriod(), minimumCacheLifetime);

  // Set up freshnessExpiryTimeMilliseconds_ which is the time time when
  // the freshness period of the content expires (independent of when to
  // remove from the cache) in milliseconds according to new Date().getTime().
  this.freshnessExpiryTimeMilliseconds_ = nowMilliseconds +
    data.getMetaInfo().getFreshnessPeriod();
};

MemoryContentCache.StaleTimeContent.prototype = new MemoryContentCache.Content();
MemoryContentCache.StaleTimeContent.prototype.name = "StaleTimeContent";

/**
 * Check if this content is stale and should be removed from the cache,
 * according to the content freshness period and the minimumCacheLifetime.
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 * @return {boolean} True if this content is stale, otherwise false.
 */
MemoryContentCache.StaleTimeContent.prototype.isPastRemovalTime = function
  (nowMilliseconds)
{
  return this.cacheRemovalTimeMilliseconds_ <= nowMilliseconds;
};

/**
 * Check if the content is still fresh according to its freshness period
 * (independent of when to remove from the cache).
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 * @return {boolean} True if the content is still fresh, otherwise false.
 */
MemoryContentCache.StaleTimeContent.prototype.isFresh = function
  (nowMilliseconds)
{
  return this.freshnessExpiryTimeMilliseconds_ > nowMilliseconds;
};

/**
 * A PendingInterest holds an interest which onInterest received but could
 * not satisfy. When we add a new data packet to the cache, we will also check
 * if it satisfies a pending interest.
 */
MemoryContentCache.PendingInterest = function MemoryContentCachePendingInterest
  (interest, face)
{
  this.interest = interest;
  this.face = face;

  // Set up timeoutMilliseconds.
  var interestLifetime = this.interest.getInterestLifetimeMilliseconds();
  if (interestLifetime == null || interestLifetime < 0.0)
    // The InterestLifetime is omitted, so use a default.
    interestLifetime = 4000.0;

  this.timeoutMilliseconds = (new Date()).getTime() + interestLifetime;
};

/**
 * Return the interest given to the constructor.
 */
MemoryContentCache.PendingInterest.prototype.getInterest = function()
{
  return this.interest;
};

/**
 * Return the face given to the constructor.
 */
MemoryContentCache.PendingInterest.prototype.getFace = function()
{
  return this.face;
};

/**
 * Check if this interest is timed out.
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 * @return {boolean} True if this interest timed out, otherwise false.
 */
MemoryContentCache.PendingInterest.prototype.isTimedOut = function(nowMilliseconds)
{
  return nowMilliseconds >= this.timeoutTimeMilliseconds;
};
