/*
 * Copyright (C) 2014-2019 Regents of the University of California.
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

var Face = require('../..').Face;
var Name = require('../..').Name;
var EncodingUtils = require('../..').EncodingUtils;

var onData = function(interest, data) {
  console.log("Data received in callback.");
  console.log('Name: ' + data.getName().toUri());
  console.log('Content: ' + data.getContent().buf().toString());
  console.log(EncodingUtils.dataToHtml(data).replace(/<br \/>/g, "\n"));

  console.log('Quit script now.');
  face.close();  // This will cause the script to quit.
};

var onTimeout = function(interest) {
  console.log("Interest time out.");
  console.log('Interest name: ' + interest.getName().toUri());
  console.log('Quit script now.');
  face.close();  // This will cause the script to quit.
};

var face = new Face();
var name = new Name("/");
console.log("Express name " + name.toUri());
face.expressInterest(name, onData, onTimeout);
