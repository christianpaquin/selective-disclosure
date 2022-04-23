const jose = require('jose');
const crypto = require('crypto');
const pbkdf2 = require('pbkdf2');

const jwt = {
    "iss": "https://example.org",
    "nbf": 1648226603.76,
    "abc": 1,
    "foo": "bar",
    "over21": true
}

const sdClaims = {
    "given_name": "Jason",
    "middle_name": "Webb",
    "family_name": "Token",
    "https://example.org/custom": "custom value"
}

const hiddenClaims = ["middle_name", "family_name"];

const digestDerivationFunctionId = "PBKDF2-HMAC-SHA256-310000"; // = "SHA256"; 

const digestDerivationFunction = (data, salt) => {
    if (digestDerivationFunctionId === "PBKDF2-HMAC-SHA256-310000") {
        return pbkdf2.pbkdf2Sync(data, salt, 310000 , 32, 'sha256');
    } else if (digestDerivationFunctionId === "SHA256") {
        return crypto.createHash('sha256').update(salt).update(data).digest();
    }
}

const processClaims = (claims) => {
    let sdData = {};
    let sdDigests = {};
    Object.keys(claims).forEach(name => {
        const salt = crypto.randomBytes(8);
        sdData[name] = {
            s: jose.base64url.encode(salt),
            v: claims[name]
        }
        sdDigests[name] = jose.base64url.encode(digestDerivationFunction(claims[name], salt));
    });
    return {sdData: sdData, sdDigests: sdDigests}
}

const getDisclosedClaims = (sdData, sdDigests) => {
    let claims = {}
    Object.keys(sdData).forEach(name => {
        const digest = sdDigests[name];
        if (digest) {
            const salt = jose.base64url.decode(sdData[name].s);
            const value = sdData[name].v;
            const digest2 = jose.base64url.encode(digestDerivationFunction(value, salt));
            if (digest === digest2) {
                // disclosed claim matches the encoded digest
                claims[name] = value;
            }
        }
    });
    return claims;
}

void (async () => {
    // generate issuer key pair
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
    
    // data to sign
    console.log("jwt to sign:", JSON.stringify(jwt, null, 2), "\n");
    console.log("selectively-disclosable claims", JSON.stringify(sdClaims, null, 2), "\n");
    console.log("digest derivation function:", digestDerivationFunctionId, "\n");

    // create sdDigests object, and add it to the jwt
    const claimInfo = processClaims(sdClaims);
    jwt.sdDigests = claimInfo.sdDigests;
    console.log("jwt with sdDigests: ", JSON.stringify(jwt, null, 2), "\n");

    // sign the jwt
    const jwsHeader = { alg: 'ES256', sdDDF: digestDerivationFunctionId };
    console.log("JWS header", JSON.stringify(jwsHeader, null, 2), "\n");
    const jwsUnprotectedHeader = { sdData: claimInfo.sdData }; 
    console.log("JWS unprotected header", JSON.stringify(jwsUnprotectedHeader, null, 2), "\n");
    let jws = await new jose.FlattenedSign(Buffer.from(JSON.stringify(jwt)))
    .setProtectedHeader(jwsHeader)
    .setUnprotectedHeader(jwsUnprotectedHeader)
    .sign(privateKey);
    console.log("jws:", JSON.stringify(jws, null, 2), "\n");

    // hide some claims
    console.log("claims to hide:", JSON.stringify(hiddenClaims, null, 2), "\n");
    hiddenClaims.forEach(name => {delete jws.header.sdData[name]});

    // verify the jws
    const result = await jose.flattenedVerify(jws,publicKey);
    const verifiedJwt = JSON.parse(result.payload);
    console.log("verified JWT", JSON.stringify(verifiedJwt, null, 2), "\n");

    // get the disclosed claim values
    const sdData = result.unprotectedHeader.sdData;
    if (sdData && verifiedJwt.sdDigests) {
        const disclosedClaims = getDisclosedClaims(sdData, verifiedJwt.sdDigests);
        console.log("disclosed claims", JSON.stringify(disclosedClaims, null, 2));
    }
})();