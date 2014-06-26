/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Name = require('../name.js').Name;

/**
 * A MemoryContentCache holds a set of Data packets and answers an Interest to
 * return the correct Data packet. The cached is periodically cleaned up to
 * remove each stale Data packet based on its FreshnessPeriod (if it has one).
 * @note This class is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
 *
 * Create a new MemoryContentCache to use the given Face.
 *
 * @param {Face} face The Face to use to call registerPrefix and which will call
 * the OnInterest callback.
 * @param {number} cleanupIntervalMilliseconds (optional) The interval
 * in milliseconds between each check to clean up stale content in the cache. If
 * omitted, use a default of 1000 milliseconds. If this is a large number, then
 * effectively the stale content will not be removed from the cache.
 */
var MemoryContentCache = function MemoryContentCache
  (face, cleanupIntervalMilliseconds)
{
  cleanupIntervalMilliseconds = (cleanupIntervalMilliseconds || 1000.0);

  this.face = face;
  this.cleanupIntervalMilliseconds = cleanupIntervalMilliseconds;
  this.nextCleanupTime = new Date().getTime() + cleanupIntervalMilliseconds;

  this.onDataNotFoundForPrefix = {}; /**< The map key is the prefix.toUri().
 *                                        The value is an OnInterest function. */
  this.noStaleTimeCache = []; /**< elements are MemoryContentCache.Content */
  this.staleTimeCache = [];   /**< elements are MemoryContentCache.StaleTimeContent */
  //StaleTimeContent::Compare contentCompare_;
  this.emptyComponent = new Name.Component();
};

exports.MemoryContentCache = MemoryContentCache;

/**
 * Call registerPrefix on the Face given to the constructor so that this
 * MemoryContentCache will answer interests whose name has the prefix.
 * @param {Name} prefix The Name for the prefix to register. This copies the Name.
 * @param {function} onRegisterFailed If this fails to register the prefix for
 * any reason, this calls onRegisterFailed(prefix) where prefix is the prefix
 * given to registerPrefix.
 * @param {function} onDataNotFound (optional) If a data packet is not found in
 * the cache, this calls onInterest(prefix, interest, transport) to forward the
 * interest. If omitted, this does not use it.
 * @param {ForwardingFlags} flags (optional) See Face::registerPrefix.
 * @param {WireFormat} wireFormat (optional) See Face::registerPrefix.
 */
MemoryContentCache.prototype.registerPrefix = function
  (prefix, onRegisterFailed, onDataNotFound, flags, wireFormat)
{
  if (onDataNotFound)
    this.onDataNotFoundForPrefix[prefix.toUri()] = onDataNotFound;
  var thisMemoryContentCache = this;
  this.face.registerPrefix
    (prefix,
     function(prefix, interest, transport)
       { thisMemoryContentCache.onInterest(prefix, interest, transport); },
     onRegisterFailed, flags, wireFormat);
};

/**
 * Add the Data packet to the cache so that it is available to use to answer
 * interests. If data.getFreshnessPeriod() is not negative, set the staleness
 * time to now plus data.getFreshnessPeriod(), which is checked during cleanup
 * to remove stale content. This also checks if cleanupIntervalMilliseconds
 * milliseconds have passed and removes stale content from the cache.
 * @param {Data} data The Data packet object to put in the cache. This copies
 * the fields from the object.
 */
MemoryContentCache.prototype.add = function(data)
{
  this.doCleanup();

  if (data.getMetaInfo().getFreshnessPeriod() != null &&
      data.getMetaInfo().getFreshnessPeriod() >= 0.0) {
    // The content will go stale, so use staleTimeCache.
    var content = new MemoryContentCache.StaleTimeContent(data);
    // Insert into staleTimeCache, sorted on content.staleTimeMilliseconds.
    // Search from the back since we expect it to go there.
    var i = this.staleTimeCache.length - 1;
    while (i >= 0) {
      if (this.staleTimeCache[i].staleTimeMilliseconds <= content.staleTimeMilliseconds)
        break;
      --i;
    }
    // Element i is the greatest less than or equal to
    // content.staleTimeMilliseconds, so insert after it.
    this.staleTimeCache.splice(i + 1, 0, content);
  }
  else
    // The data does not go stale, so use noStaleTimeCache.
    this.noStaleTimeCache.push(new MemoryContentCache.Content(data));
}

/**
 * This is the OnInterest callback which is called when the library receives
 * an interest whose name has the prefix given to registerPrefix. First check
 * if cleanupIntervalMilliseconds milliseconds have passed and remove stale
 * content from the cache. Then search the cache for the Data packet, matching
 * any interest selectors including ChildSelector, and send the Data packet
 * to the transport. If no matching Data packet is in the cache, call
 * the callback in onDataNotFoundForPrefix (if defined).
 */
MemoryContentCache.prototype.onInterest = function(prefix, interest, transport)
{
  this.doCleanup();

  var selectedComponent = 0;
  var selectedEncoding = null;
  // We need to iterate over both arrays.
  var totalSize = this.staleTimeCache.length + this.noStaleTimeCache.length;
  for (var i = 0; i < totalSize; ++i) {
    var content;
    if (i < this.staleTimeCache.length)
      content = this.staleTimeCache[i];
    else
      // We have iterated over the first array. Get from the second.
      content = this.noStaleTimeCache[i - this.staleTimeCache.length];

    if (interest.matchesName(content.getName())) {
      if (interest.getChildSelector() < 0) {
        // No child selector, so send the first match that we have found.
        transport.send(content.getDataEncoding());
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
    transport.send(selectedEncoding);
  else {
    // Call the onDataNotFound callback (if defined).
    var onDataNotFound = this.onDataNotFoundForPrefix[prefix.toUri()];
    if (onDataNotFound)
      // TODO: Include registeredPrefixId.
      onDataNotFound(prefix, interest, transport);
  }
};

/**
 * Check if now is greater than nextCleanupTime and, if so, remove stale
 * content from staleTimeCache and reset nextCleanupTime based on
 * cleanupIntervalMilliseconds. Since add(Data) does a sorted insert into
 * staleTimeCache, the check for stale data is quick and does not require
 * searching the entire staleTimeCache.
 */
MemoryContentCache.prototype.doCleanup = function()
{
  var now = new Date().getTime();
  if (now >= this.nextCleanupTime) {
    // staleTimeCache is sorted on staleTimeMilliseconds, so we only need to
    // erase the stale entries at the front, then quit.
    while (this.staleTimeCache.length > 0 && this.staleTimeCache[0].isStale(now))
      this.staleTimeCache.shift();

    this.nextCleanupTime = now + this.cleanupIntervalMilliseconds;
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
 * StaleTimeContent extends Content to include the staleTimeMilliseconds for
 * when this entry should be cleaned up from the cache.
 *
 * Create a new StaleTimeContent to hold data's name and wire encoding as well
 * as the staleTimeMilliseconds which is now plus
 * data.getMetaInfo().getFreshnessPeriod().
 * @param {Data} data The Data packet whose name and wire encoding are copied.
 */
MemoryContentCache.StaleTimeContent = function MemoryContentCacheStaleTimeContent
  (data)
{
  // Call the base constructor.
  MemoryContentCache.Content.call(this, data);

  // Set up staleTimeMilliseconds which is The time when the content becomse
  // stale in milliseconds according to new Date().getTime().
  this.staleTimeMilliseconds = new Date().getTime() +
    data.getMetaInfo().getFreshnessPeriod();
};

MemoryContentCache.StaleTimeContent.prototype = new MemoryContentCache.Content();
MemoryContentCache.StaleTimeContent.prototype.name = "StaleTimeContent";

/**
 * Check if this content is stale.
 * @param {number} nowMilliseconds The current time in milliseconds from
 * new Date().getTime().
 * @returns {boolean} true if this interest is stale, otherwise false.
 */
MemoryContentCache.StaleTimeContent.prototype.isStale = function(nowMilliseconds)
{
  return this.staleTimeMilliseconds <= nowMilliseconds;
};
