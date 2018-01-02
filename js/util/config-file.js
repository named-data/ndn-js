/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From https://github.com/named-data/ndn-cxx/blob/master/src/util/config-file.hpp
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
var fs = require('fs'); /** @ignore */
var path = require('path'); /** @ignore */
var BasicIdentityStorage = require('../security//identity/basic-identity-storage').BasicIdentityStorage;

/**
 * A ConfigFile locates, opens, and parses a library configuration file, and
 * holds the values for the application to get.
 *
 * Locate, open, and parse a library configuration file.
 * @constructor
 */
var ConfigFile = function ConfigFile()
{
  this.path_ = ConfigFile.findConfigFile_();
  this.config_ = {};

  if (this.path_ !== "")
    this.parse_();
};

exports.ConfigFile = ConfigFile;

/**
 * Get the value for the key, or a default value if not found.
 * @param {string} key The key to search for.
 * @param {string}  defaultValue The default value if the key is not found.
 * @return {string}  The value, or defaultValue if the key is not found.
 */
ConfigFile.prototype.get = function(key, defaultValue)
{
  if (this.config_[key] !== undefined)
    return this.config_[key];
  else
    return defaultValue;
};

/**
 * Get the path of the configuration file.
 * @return {string} The path or an empty string if not found.
 */
ConfigFile.prototype.getPath = function() { return this.path_; };

/**
 * Get the configuration key/value pairs.
 * @return {object} An associative array of the key/value pairs.
 */
ConfigFile.prototype.getParsedConfiguration = function() { return this.config_; };

/**
 * Look for the configuration file in these well-known locations:
 *
 * 1. $HOME/.ndn/client.conf
 * 2. /etc/ndn/client.conf
 * We don't support the C++ #define value @SYSCONFDIR@.
 *
 * @return {string} The path of the config file or an empty string if not found.
 */
ConfigFile.findConfigFile_ = function()
{
  var filePath = path.join
    (BasicIdentityStorage.getUserHomePath(), ".ndn", "client.conf");
  try {
    fs.accessSync(filePath, fs.F_OK);
    return filePath;
  } catch (e) {}

  // Ignore the C++ SYSCONFDIR.

  filePath = "/etc/ndn/client.conf";
  try {
    fs.accessSync(filePath, fs.F_OK);
    return filePath;
  } catch (e) {}

  return "";
};

/**
 * Open path_, parse the configuration file and set config_.
 */
ConfigFile.prototype.parse_ = function()
{
  if (this.path_ === "")
    throw new Error
      ("ConfigFile.parse: Failed to locate the configuration file for parsing");

  // Use readFileSync instead of the asycnronous readline.
  input = fs.readFileSync(this.path_).toString();

  var thisConfig = this;
  input.split(/\r?\n/).forEach(function(line) {
    line = line.trim();
    if (line === "" || line[0] === ';')
      // Skip empty lines and comments.
      return;

    var iSeparator = line.indexOf('=');
    if (iSeparator < 0)
      return;

    var key = line.substr(0, iSeparator).trim();
    var value = line.substr(iSeparator + 1).trim();

    thisConfig.config_[key] = value;
  });
};
