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
 * A ChangeCounter keeps a target object whose change count is tracked by a
 * local change count.  You can set to a new target which updates the local
 * change count, and you can call checkChanged to check if the target (or one of
 * the target's targets) has been changed. The target object must have a method
 * getChangeCount.
 *
 * Create a new ChangeCounter to track the given target. If target is not null,
 * this sets the local change counter to target.getChangeCount().
 * @param {object} target The target to track, as an object with the method
 * getChangeCount().
 * @constructor
 */
var ChangeCounter = function ChangeCounter(target)
{
  this.target = target;
  this.changeCount = (target == null ? 0 : target.getChangeCount());
};

exports.ChangeCounter = ChangeCounter;

/**
 * Get the target object. If the target is changed, then checkChanged will
 * detect it.
 * @return {object} The target, as an object with the method
 * getChangeCount().
 */
ChangeCounter.prototype.get = function()
{
  return this.target;
};

/**
 * Set the target to the given target. If target is not null, this sets the
 * local change counter to target.getChangeCount().
 * @param {object} target The target to track, as an object with the method
 * getChangeCount().
 */
ChangeCounter.prototype.set = function(target)
{
  this.target = target;
  this.changeCount = (target == null ? 0 : target.getChangeCount());
};

/**
 * If the target's change count is different than the local change count, then
 * update the local change count and return true. Otherwise return false,
 * meaning that the target has not changed. Also, if the target is null,
 * simply return false. This is useful since the target (or one of the target's
 * targets) may be changed and you need to find out.
 * @return {boolean} True if the change count has been updated, false if not.
 */
ChangeCounter.prototype.checkChanged = function()
{
  if (this.target == null)
    return false;

  var targetChangeCount = this.target.getChangeCount();
  if (this.changeCount != targetChangeCount) {
    this.changeCount = targetChangeCount;
    return true;
  }
  else
    return false;
};
