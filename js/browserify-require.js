/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Ryan Bennett
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

// define a shim require function so that a node/browserify require calls dont cause errors when ndn-js is used via <script> tag

/** @ignore */
var ndn = ndn || {}
/** @ignore */
var exports = ndn;

/** @ignore */
var module = {}
/** @ignore */
function require(){return ndn;}
