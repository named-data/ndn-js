/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/validator-config.cpp
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
var CertificateFetcher = require('./v2/certificate-fetcher.js').CertificateFetcher; /** @ignore */
var ValidationPolicyConfig = require('./v2/validation-policy-config.js').ValidationPolicyConfig; /** @ignore */
var CertificateFetcherFromNetwork = require('./v2/certificate-fetcher-from-network.js').CertificateFetcherFromNetwork; /** @ignore */
var Validator = require('./v2/validator.js').Validator;

/**
 * ValidatorConfig extends Validator to implements a validator which can be
 * set up via a configuration file.
 *
 * The constructor has two forms:
 * ValidatorConfig(fetcher) - Create a ValidatorConfig that uses the given
 * certificate fetcher.
 * ValidatorConfig(face) - Create a ValidatorConfig that uses a
 * CertificateFetcherFromNetwork for the given Face.
 * @param {CertificateFetcher} fetcher the certificate fetcher to use.
 * @param {Face} face The face for the certificate fetcher to call
 * expressInterest.
 * @constructor
 */
var ValidatorConfig = function ValidatorConfig(fetcherOrFace)
{
  if (fetcherOrFace instanceof CertificateFetcher) {
    // Call the base constructor.
    Validator.call(this, new ValidationPolicyConfig(), fetcherOrFace);
    // TODO: Use getInnerPolicy().
    this.policyConfig_ = this.getPolicy();
  }
  else {
    // Call the base constructor.
    Validator.call
      (this, new ValidationPolicyConfig(),
       new CertificateFetcherFromNetwork(fetcherOrFace));
    // TODO: Use getInnerPolicy().
    this.policyConfig_ = this.getPolicy();
  }
};

ValidatorConfig.prototype = new Validator
  (new ValidationPolicyConfig(), new CertificateFetcherFromNetwork(null));
ValidatorConfig.prototype.name = "ValidatorConfig";

exports.ValidatorConfig = ValidatorConfig;

/**
 * There are three forms of load:
 * load(filePath) - Load the configuration from the given config file.
 * load(input, inputName) - Load the configuration from the given input string.
 * load(configSection, inputName) - Load the configuration from the given
 * configSection.
 * Each of these forms of load replaces any existing configuration.
 * @param {String} filePath The The path of the config file.
 * @param {String} input The contents of the configuration rules, with lines
 * separated by "\n" or "\r\n".
 * @param {BoostInfoTree} The configuration section loaded from the config file.
 * It should have one "validator" section.
 * @param {String} inputName Used for log messages, etc.
 */
ValidatorConfig.prototype.load = function
  (filePathOrInputOrConfigSection, inputName)
{
  this.policyConfig_.load(filePathOrInputOrConfigSection, inputName);
};
