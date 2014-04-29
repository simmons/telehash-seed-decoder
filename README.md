Telehash seeds.json decoder tool
====================

This is a simple Javascript web app for decoding a pasted Telehash
seeds.json structure or a Base64-encoded RSA public key.  For public
keys, the ASN.1 structure and calculated fingerprint are revealed, and
for a full seeds.json the hashname calculation steps are provided.

External libraries included herein
--------------------

1. Bootstrap (MIT license)
2. ASN.1 Javascript decoder [home](http://lapo.it/asn1js/) [github](https://github.com/lapo-luchini/asn1js) (ISC license - MIT-like)
3. jQuery (MIT license)
4. jssha256 by B. Poettering (GPL)


