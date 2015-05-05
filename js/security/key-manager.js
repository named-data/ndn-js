/**
 * Copyright (C) 2013-2015 Regents of the University of California.
 * @author: Meki Cheraoui
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

var Key = require('../key.js').Key;
var WireFormat = require('../encoding/wire-format.js').WireFormat;

/**
 * @deprecated NDNx-style key management is deprecated. Use KeyChain.
 * @constructor
 */
var KeyManager = function KeyManager()
{
  // Public Key
    this.publicKey_ =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuAmnWYKE7E8G+hyy4TiT\n"	+
  "U7t91KyIGvglEeT6HWEkW4LKzXLO22a1jVS9+yP96I6vp7N5vpS1t7oXtgWuzkO+\n" +
  "O85u6gfbvwp+67zJe2I89eHO4dmNnP4fx/j7WcCUCyzZfbyW67h5IoouoBIdQge2\n" +
  "Xdvh9rFdex9UUhyjEZv5676zlcqlhz8xGBrJmQHsqpD9ijY1XhKBvoSIoQ0ZKkpm\n" +
  "wVk8QYM9PbjUqzSQBj4aYXS+BPV6aRudVvyDt2DBXp2FNP0CGrosCXKnSl4Yv8BY\n" +
  "p0k0RmFZDuJuntLb/XIvPEfMX5li7g3zHzAlIJIVSwT+FRkd3H5cECFSIZFUYIuS\n" +
  "QQIDAQAB\n" +
  "-----END PUBLIC KEY-----";
  // Private Key
    this.privateKey_ =
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIIEpQIBAAKCAQEAuAmnWYKE7E8G+hyy4TiTU7t91KyIGvglEeT6HWEkW4LKzXLO\n"	+
  "22a1jVS9+yP96I6vp7N5vpS1t7oXtgWuzkO+O85u6gfbvwp+67zJe2I89eHO4dmN\n" +
  "nP4fx/j7WcCUCyzZfbyW67h5IoouoBIdQge2Xdvh9rFdex9UUhyjEZv5676zlcql\n" +
  "hz8xGBrJmQHsqpD9ijY1XhKBvoSIoQ0ZKkpmwVk8QYM9PbjUqzSQBj4aYXS+BPV6\n" +
  "aRudVvyDt2DBXp2FNP0CGrosCXKnSl4Yv8BYp0k0RmFZDuJuntLb/XIvPEfMX5li\n" +
  "7g3zHzAlIJIVSwT+FRkd3H5cECFSIZFUYIuSQQIDAQABAoIBAQCKBftzfxavn6lM\n" +
  "5T8m+GZN0vzRBsBg8Z/jpsYKSLOayiHNKYCIPaSFpXuCIYEo6/JDJLB2xVLvwupL\n" +
  "gkGSwm2mrvCyJkihI38Cz6iQF6I+iia9bYrupgwxzsK7klm1c+J9kXXivYxj4hyL\n" +
  "wmoc/mnARMtYV7cTQvDbUEzgRQmPykWKBv6Y0SL1WprfiRfKIMwSqQk91ffj6whK\n" +
  "xBLAuUdseVBmo/ivLPq0a+wDrcvaJAxSB4eIwCHzAugkRA/NoK0vG3mra0lK5jvQ\n" +
  "rcNIuffxNAnresDVDTnYRc42etjePLAhlpeK/4sjYE/wPdeP8yzLHUg/hsSpAPIj\n" +
  "LXJNZqUBAoGBANxPmUQNf1lGHo/nLY3dVMD3+kYNnTUD8XwS81qdg8/dNyF8t+7D\n" +
  "OdJ1j7Itb+zGA1XXAGfTm6JoUG+eKKR2OSuyZcxygpOgzxAFanXKhTWZsKbG70xN\n" +
  "mX0sOAEhtTGsgFTEGEv977MwIlFa6n2bsp3Luj/AGmvNsOYvBDPXOklxAoGBANXZ\n" +
  "yXAaE7M5JALusLuEFxLGvWVz6TRdQ//c+FWvKrnh+nFlTlAPpDvlaPJJca8ViNev\n" +
  "xJ2UhGtbENXAqgwTYpnAi/yQD4dATViIveK6Pn4t12mpPAlkMbbMTR8jtp5l1oHc\n" +
  "hcwe8QuEOKuTX5+STpNGlWs+tsMb12mhCpc3eO3RAoGAMxjDE2WOA8afkACuMBkF\n" +
  "bzwUb+r4azNe7sf2aS3fRHaqMroabuYYoxdhHJItQ10pqN8U2P/bOO+4uCqWgo5o\n" +
  "9BmMQr7MSjEh1TVsW6V8/9GFhyjcl3XoA4Ad/SU0QTEhEofomrdqwMSJMRVFDZzu\n" +
  "8Gov6FlFx3sNbFW7Q8rHWgECgYEAq/TVz3iIgsLdvCXmosHSM9zvCpcr3FlqhmFO\n" +
  "pseVmaamVWxajnIlY6xSuRBpg5nTUWwas4Nq/1BYtyiXE+K6lFuJtOq6Mc145EoA\n" +
  "NkIAYkHGR0Y36m1QtGaPVQzImZHV7NJAHCR9Ov90+jIk4BErca1+FKB3IWhPzLYb\n" +
  "6ABJEyECgYEAthhzWSxPkqyiLl+2vnhdR3EEkvDX6MV6hGu4tDAf2A1Y0GSApyEa\n" +
  "SAA31hlxu5EgneLD7Ns2HMpIfQMydB5lcwKQc9g/tVI1eRzuk6Myi+2JmPEM2BLy\n" +
  "iX8yI+xnZlKDiZleQitCS4RQGz5HbXT70aYQIGxuvkQ/uf68jdrL6o8=\n" +
  "-----END RSA PRIVATE KEY-----";

  this.key = null;
};

/**
 * Return a Key object for the keys in this KeyManager.  This creates the Key on the first
 * call and returns a cached copy after that.
 * @returns {Key}
 * @deprecated NDNx-style key management is deprecated. Use KeyChain.
 */
KeyManager.prototype.getKey = function()
{
  if (this.key === null) {
    this.key = new Key();
    this.key.fromPemString(this.publicKey_, this.privateKey_);
  }

  return this.key;
}

Object.defineProperty(KeyManager.prototype, "publicKey",
  { get: function() {
      if (!WireFormat.ENABLE_NDNX)
        throw new Error
          ("NDNx-style key management is deprecated. To enable while you upgrade your code to use KeyChain, set WireFormat.ENABLE_NDNX = true");

      return this.publicKey_;
    } });
Object.defineProperty(KeyManager.prototype, "privateKey",
  { get: function() {
      if (!WireFormat.ENABLE_NDNX)
        throw new Error
          ("NDNx-style key management is deprecated. To enable while you upgrade your code to use KeyChain, set WireFormat.ENABLE_NDNX = true");

      return this.privateKey_;
    } });

var globalKeyManager = globalKeyManager || new KeyManager();
exports.globalKeyManager = globalKeyManager;
