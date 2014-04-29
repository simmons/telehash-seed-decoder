
function byteArrayToString(bin) {
    var buffer = "";
    for (var i=0; i<bin.length; i++) {
        buffer += String.fromCharCode(bin[i]);
    }
    return buffer;
}

function base64encode(bin) {
    return window.btoa(byteArrayToString(bin));
}

function hexEncode(bin) {
    var buffer = "";
    for (var i=0; i<bin.length; i++) {
        var code = bin[i];
        buffer += code.toString(16)+" ";
    }
    return buffer;
}

function errorClear() {
    $('#errors').empty();
}
function error(msg) {
    $('#errors').append('<p>'+msg+'</p>');
    var errorsDiv = document.getElementById("errors");
}

//
// Parse an RSA public key assuming X.509 SubjectPublicKeyInfo format
//
function parseSPKI(asn1) {
    try {
        if (asn1.typeName() == "SEQUENCE" &&
            asn1.sub[0].typeName() == "SEQUENCE" &&
            asn1.sub[0].sub[0].typeName() == "OBJECT_IDENTIFIER" &&
            asn1.sub[0].sub[0].content() == "1.2.840.113549.1.1.1" &&
            asn1.sub[1].sub[0].sub[0].typeName() == "INTEGER" &&
            asn1.sub[1].sub[0].sub[1].typeName() == "INTEGER") {
                return [
                    asn1.sub[1].sub[0].sub[0].content(),
                    asn1.sub[1].sub[0].sub[1].content()
                ];
        }
    } catch (e) {
        return null;
    }
    return null;
}

//
// Parse an RSA public key assuming PKCS#1v2.1 format.
//
function parsePkcs1v21(asn1) {
    try {
        if (asn1.typeName() == "SEQUENCE" &&
            asn1.sub[0].typeName() == "INTEGER" &&
            asn1.sub[1].typeName() == "INTEGER") {
            return [
                asn1.sub[0].content(),
                asn1.sub[1].content()
            ];
        }
    } catch (e) {
        return null;
    }
    return null;
}

function asn1ToBytes(asn1) {
    return asn1.stream.enc.slice(asn1.stream.pos, asn1.stream.pos+asn1.header+asn1.length);
}

function encodeDERLength(length) {
    if (length > 127) {
        if (length > 65535) {
            throw new Error("unsupported DER length");
        }
        encodedLength = [ 0x82, ((length&0xFF00)>>8), (length&0xFF) ];
    } else {
        encodedLength = [ length ];
    }
    return encodedLength;
}

function convertSPKIToPkcs1v21(asn1) {
    var encodedModulus = asn1ToBytes(asn1.sub[1].sub[0].sub[0]);
    var encodedExponent = asn1ToBytes(asn1.sub[1].sub[0].sub[1]);
    var sequenceLength = encodedModulus.length + encodedExponent.length;
    var encodedSequenceLength = encodeDERLength(sequenceLength);
    return [0x30].concat(encodedSequenceLength, encodedModulus, encodedExponent);
}

function convertPkcs1v21ToSPKI(asn1) {
    // wrap in BIT STRING
    var pkcs1Key = asn1ToBytes(asn1);
    var bitString = [0x03].concat(
        encodeDERLength(1+pkcs1Key.length),
        [0x00],
        pkcs1Key
    );
    // form SEQUENCE{rsaAlgorithm,NULL}
    var algorithmSequence = [ 
        0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,
        0xF7,0x0D,0x01,0x01,0x01,0x05,0x00
    ];
    // combine into outer SEQUENCE
    var sequence = [0x30].concat(
        encodeDERLength(algorithmSequence.length+bitString.length),
        algorithmSequence,
        bitString
    );
    return sequence;
}

function sha256(data) {
    SHA256_init();
    SHA256_write(data);
    digest = SHA256_finalize();
//    digest_hex = array_to_hex_string(digest);
    return digest;
}

function sha256hex(data) {
    SHA256_init();
    SHA256_write(data);
    digest = SHA256_finalize();
    digest_hex = array_to_hex_string(digest);
    return digest_hex;
}

function decodeKey(li, key64, providedFingerprint) {
    try {
        var key = Base64.decode(key64);
        var asn1 = ASN1.decode(key);
        li.append("<p><b><u>Cipher set 2a RSA public key</u></b></p>");
        li.append("<p>DER/ASN.1 structure:</p>");
        li.append("<p><pre>"+asn1.toPrettyString()+"</pre></p>");

        var parsedKey;
        var correctKey;
        var fingerprint;
        if ((parsedKey = parseSPKI(asn1)) != null) {
            li.append("<p>Public key is in <b>X.509 SubjectPublicKeyInfo</b> format, and contains the following values:</p>");
            li.append("<p><pre>Modulus: "+parsedKey[0]+"\nExponent: "+parsedKey[1]+"</pre></p>");

            correctKey = key;
            fingerprint = sha256hex(correctKey);
            li.append("<p>Calculated public key fingerprint (X.509 SPKI encoding): <tt><b>"+fingerprint+"</b></tt></p>");

            if (providedFingerprint) {
                if (providedFingerprint != fingerprint) {
                    li.append('<p class="error">The seeds.json "part" for this key is not the correct fingerprint!</p>');
                }
            }
        } else if ((parsedKey = parsePkcs1v21(asn1)) != null) {
            li.append("<p>Public key is in <b>PKCS#1 v2.1</b> format, and contains the following values:</p>");
            li.append("<p><pre>Modulus: "+parsedKey[0]+"\nExponent: "+parsedKey[1]+"</pre></p>");

            // warn about incorrect format
            li.append('<p class="error">The public key should be provided in X.509 SubjectPublicKeyInfo encoding, as follows:</p>');
            correctKey = convertPkcs1v21ToSPKI(asn1);
            li.append("<p><pre>"+base64encode(correctKey)+"</pre></p>");

            fingerprint = sha256hex(correctKey);
            li.append("<p>Calculated public key fingerprint (X.509 SPKI encoding): <tt><b>"+fingerprint+"</b></tt></p>");

            if (providedFingerprint) {
                var badFingerprint = sha256hex(key);
                var goodFingerprint = fingerprint;
                if (providedFingerprint != goodFingerprint) {
                    if (providedFingerprint == badFingerprint) {
                        li.append('<p class="error">The seeds.json "part" for this key is not the correct fingerprint!  (It is actually a fingerprint of the PKCS#1 v2.1 encoding!)</p>');
                    } else {
                        li.append('<p class="error">The seeds.json "part" for this key is not the correct fingerprint!</p>');
                    }
                }
            }
        } else {
            li.append('<p class="error">The public key is not encoded in a known format.</p>');
            return;
        }
        return fingerprint;
    } catch (e) {
        if (e.stack) {
            error(e.stack);
        } else {
            error(e);
        }
    }
}

function calculateHashname(li, parts) {
    var work = "";
    var hash = null;
    Object.keys(parts).sort().forEach(function(id){
        if (hash == null) {
            hash = sha256(id);
            work += 'hash = sha256("'+id+'");'+"\n"+'// '+array_to_hex_string(hash)+"\n";
        } else {
            hash = sha256(byteArrayToString(hash) + id);
            work += 'hash = sha256(hash + "'+id+'");'+"\n"+'// '+array_to_hex_string(hash)+"\n";
        }
        hash = sha256(byteArrayToString(hash) + parts[id]);
        work += 'hash = sha256(hash + "'+parts[id]+'");'+"\n"+'// '+array_to_hex_string(hash)+"\n";
    });
    var calcHashname = array_to_hex_string(hash);
    li.append("<p><pre>"+work+"</pre></p>");

    return calcHashname;
}

function decode() {
    errorClear();
    var output = $("#output");
    output.empty();
    var ul = $("<ul></ul");
    output.append(ul);

    var text = document.getElementById("seeds").value;
    if (! text) {
        error("Empty string -- bailing.");
        return;
    }

    // is the text just a public key (not JSON)?
    if (! (text.indexOf("{") > -1)) {
        var li = $("<li></li>");
        ul.append(li);
        decodeKey(li, text);
        return;
    }

    try {
        // JSON decode
        var obj = jQuery.parseJSON(text);

        for (var hashname in obj) {
            var updatedFingerprints = false;
            var goodParts = {};
            var li = $("<li></li>");
            ul.append(li);
            li.append($("<h4>hashname <tt>"+hashname+"</tt></h4>"));

            var seed = obj[hashname];
            if (! seed) {
                error("No details for hashname: "+hashname);
                continue;
            }
            var keys = seed['keys'];
            if (! keys) {
                error("No keys for hashname: "+hashname);
                continue;
            }
            var parts = seed['parts'];
            if (! parts) {
                error("No parts for hashname: "+hashname);
                continue;
            }
            for (var csid in parts) {
                goodParts[csid] = parts[csid];
                if (! keys[csid]) {
                    error("Cipher set id "+csid+" exists in parts, but not keys, in seed: "+hashname);
                }
            }
            for (var csid in keys) {
                if (! parts[csid]) {
                    error("Cipher set id "+csid+" exists in keys, but not parts, in seed: "+hashname);
                    continue;
                }
                if (csid == '2a') {
                    var fingerprint = decodeKey(li, keys[csid], parts[csid]);
                    if (fingerprint && fingerprint != parts[csid]) {
                        goodParts[csid] = fingerprint;
                        updatedFingerprints = true;
                    }
                }
            }

            li.append("<p>Hashname calculation work, based on the provided \"parts\":</p>");
            var calculatedHashname = calculateHashname(li, parts);
            li.append("<p>Calculated hashname: <b>"+calculatedHashname+"</b></p>");
            if (hashname != calculatedHashname) {
                li.append('<p class="error">Calculated hashname does not match the provided hashname!</p>');
            }

            if (updatedFingerprints) {
                li.append("<p>Hashname calculation work, based on the <b><em>correct fingerprints</em></b>:</p>");
                var calculatedHashname = calculateHashname(li, goodParts);
                li.append("<p>Calculated hashname: <b>"+calculatedHashname+"</b></p>");
                if (hashname != calculatedHashname) {
                    li.append('<p class="error">Calculated hashname (based on correct fingerprints) does not match the provided hashname!</p>');
                }
            }
        }
    } catch (e) {
        if (e.stack) {
            error(e.stack);
        } else {
            error(e);
        }
    }
}

document.getElementById("decode").onclick = decode;

