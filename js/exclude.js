/**
 * This class represents an Interest Exclude.
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Meki Cheraoui
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
var Name = require('./name.js').Name; /** @ignore */
var DataUtils = require('./encoding/data-utils.js').DataUtils; /** @ignore */
var Blob = require('./util/blob.js').Blob;

/**
 * Create a new Exclude.
 * @constructor
 * @param {Array<Name.Component|Buffer|Exclude.ANY>} values (optional) An array where each element is either a Name.Component, Buffer component or Exclude.ANY.
 */
var Exclude = function Exclude(values)
{
  this.values = [];

  if (typeof values === 'object' && values instanceof Exclude)
    // Copy the exclude.
    this.values = values.values.slice(0);
  else if (values) {
    // Set the changeCount now since append expects it.
    this.changeCount = 0;
    for (var i = 0; i < values.length; ++i) {
      if (values[i] == Exclude.ANY)
        this.appendAny();
      else
        this.appendComponent(values[i]);
    }
  }

  this.changeCount = 0;
};

exports.Exclude = Exclude;

Exclude.ANY = "*";

/**
 * Get the number of entries.
 * @return {number} The number of entries.
 */
Exclude.prototype.size = function() { return this.values.length; };

/**
 * Get the entry at the given index.
 * @param {number} i The index of the entry, starting from 0.
 * @return {Exclude.ANY|Name.Component} Exclude.ANY or a Name.Component.
 */
Exclude.prototype.get = function(i) { return this.values[i]; };

/**
 * Append an Exclude.ANY element.
 * @return This Exclude so that you can chain calls to append.
 */
Exclude.prototype.appendAny = function()
{
  this.values.push(Exclude.ANY);
  ++this.changeCount;
  return this;
};

/**
 * Append a component entry, copying from component.
 * @param {Name.Component|Buffer} component
 * @return This Exclude so that you can chain calls to append.
 */
Exclude.prototype.appendComponent = function(component)
{
  this.values.push(new Name.Component(component));
  ++this.changeCount;
  return this;
};

/**
 * Clear all the entries.
 */
Exclude.prototype.clear = function()
{
  ++this.changeCount;
  this.values = [];
};

/**
 * Return a string with elements separated by "," and Exclude.ANY shown as "*".
 */
Exclude.prototype.toUri = function()
{
  if (this.values == null || this.values.length == 0)
    return "";

  var result = "";
  for (var i = 0; i < this.values.length; ++i) {
    if (i > 0)
      result += ",";

    if (this.values[i] == Exclude.ANY)
      result += "*";
    else
      result += this.values[i].toEscapedString();
  }
  return result;
};

/**
 * Return true if the component matches any of the exclude criteria.
 */
Exclude.prototype.matches = function(component)
{
  if (!(typeof component == 'object' && component instanceof Name.Component))
    component = new Name.Component(component);

  for (var i = 0; i < this.values.length; ++i) {
    if (this.values[i] == Exclude.ANY) {
      var lowerBound = null;
      if (i > 0)
        lowerBound = this.values[i - 1];

      // Find the upper bound, possibly skipping over multiple ANY in a row.
      var iUpperBound;
      var upperBound = null;
      for (iUpperBound = i + 1; iUpperBound < this.values.length; ++iUpperBound) {
        if (this.values[iUpperBound] != Exclude.ANY) {
          upperBound = this.values[iUpperBound];
          break;
        }
      }

      // If lowerBound != null, we already checked component equals lowerBound on the last pass.
      // If upperBound != null, we will check component equals upperBound on the next pass.
      if (upperBound != null) {
        if (lowerBound != null) {
          if (component.compare(lowerBound) > 0 &&
              component.compare(upperBound) < 0)
            return true;
        }
        else {
          if (component.compare(upperBound) < 0)
            return true;
        }

        // Make i equal iUpperBound on the next pass.
        i = iUpperBound - 1;
      }
      else {
        if (lowerBound != null) {
            if (component.compare(lowerBound) > 0)
              return true;
        }
        else
          // this.values has only ANY.
          return true;
      }
    }
    else {
      if (component.equals(this.values[i]))
        return true;
    }
  }

  return false;
};

/**
 * Return -1 if component1 is less than component2, 1 if greater or 0 if equal.
 * A component is less if it is shorter, otherwise if equal length do a byte comparison.
 */
Exclude.compareComponents = function(component1, component2)
{
  if (typeof component1 == 'object' && component1 instanceof Name.Component)
    component1 = component1.getValue().buf();
  if (typeof component2 == 'object' && component2 instanceof Name.Component)
    component2 = component2.getValue().buf();

  return Name.Component.compareBuffers(component1, component2);
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @return {number} The change count.
 */
Exclude.prototype.getChangeCount = function()
{
  return this.changeCount;
};
