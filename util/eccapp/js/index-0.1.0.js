/*
	ECC App

	- Generate X509 Key Pair using Ed25519 and save to .pem file based on members:
		- First Name
		- Last Name
		- Unique ID

	- Create a certificate request and save to file as .csc using the same filename format

	openssl:
		- openssl genpkey -algorithm ed25519 -out member-test.pem

		MC4CAQAwBQYDK2VwBCIEIJ/Nn90uoHuf4GJvNtpSRmzBDhy5skxHFU5zZzNEbYkh
		MC4CAQAwBQYDK2VwBCIEIM/helYV+8ZACZ+rjYGqBhhIPFPJE5aslwwx7rayLpZ1
*/

//First, generate an Ed25519 key pair

// Generate an Ed25519 key pair

window.eccapp =
{
	x509: {data: {}},
	x509b: {data: {}},
	util: {}
}

// GOOD

window.eccapp.x509b.arrayToHex = function (array)
{
	return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

window.eccapp.x509b.hexToArrayBuffer = function (hex)
{
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
	}
	return bytes.buffer;
}

window.eccapp.x509b.generateCSR = function()
{
	// Get Ed25519 key pair generated earlier;

	const keyPair = eccapp.x509.data.keyPair;
	const privateKey = keyPair.secretKey;
	const publicKey = keyPair.publicKey;

	 const info =
	 {
		commonName: eccapp.x509.data.info.firstname.toLowerCase() + "." + eccapp.x509.data.info.lastname.toLowerCase() + "." + eccapp.x509.data.info.code + ".council.eastern.cardano",
		countryName: eccapp.x509.data.info.country,
		stateName: eccapp.x509.data.info.state,
		locationName: eccapp.x509.data.info.location,
		organizationName: "Eastern Cardano Council",
		organizationalUnitName: "Operations"
	};

	// Create subject with empty fields
	const subject = new KJUR.asn1.x509.X500Name({
		array: [
			[{type: 'C', value: info.countryName}],
			[{type: 'ST', value: info.stateName}],
			[{type: 'L', value: info.locationName}],
			[{type: 'O', value: info.organizationName}],
			[{type: 'OU', value: info.organizationalUnitName}],
			[{type: 'CN', value: info.commonName}]
		]
	});

	// Create public key info
	const ed25519Oid = new KJUR.asn1.DERObjectIdentifier({oid: '1.3.101.112'}); // OID for Ed25519
	const publicKeyAlg = new KJUR.asn1.DERSequence({array: [ed25519Oid]});
	const publicKeyBitString = new KJUR.asn1.DERBitString({
		hex: '00' + window.eccapp.x509b.arrayToHex(publicKey)
	});

	const subjectPublicKeyInfo = new KJUR.asn1.DERSequence({
		array: [
			publicKeyAlg,
			publicKeyBitString
		]
	});

	// Create CSR info
	const csrInfo = new KJUR.asn1.DERSequence({
		array: [
			new KJUR.asn1.DERInteger({'int': 0}),
			subject,
			subjectPublicKeyInfo,
			// Removed the NULL attribute
		]
	});

	// Sign the CSR
	const csrInfoHex = csrInfo.getEncodedHex();
	const signature = nacl.sign.detached(new Uint8Array(window.eccapp.x509b.hexToArrayBuffer(csrInfoHex)), privateKey);

	// Create full CSR
	const csr = new KJUR.asn1.DERSequence({
		array: [
			csrInfo,
			new KJUR.asn1.DERSequence({array: [ed25519Oid]}),
			new KJUR.asn1.DERBitString({
				hex: '00' + window.eccapp.x509b.arrayToHex(signature)
			})
		]
	});

	// Get PEM format
	const csrPEM = KJUR.asn1.ASN1Util.getPEMStringFromHex(csr.getEncodedHex(), 'CERTIFICATE REQUEST');

	window.eccapp.x509b.data.csrPEM = csrPEM;

	console.log(csrPEM);

	window.eccapp.util.saveCSRToFile(csrPEM);
}

// UTIL

window.eccapp.util.debugLog = function(step, data) {
    console.log(`${step}:`, eccapp.util.arrayBufferToHex(data));
};

window.eccapp.util.arrayBufferToBase64 = function (arrayBuffer)
{
	const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
    //const base64 = btoa(String.fromCharCode.apply(null, arrayBuffer));
	return base64;
}

window.eccapp.util.arrayBufferToPem = function (arrayBuffer, label)
{
	const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
	return "-----BEGIN " + label + "-----\n" + base64.match(/.{1,64}/g).join('\n') + "\n-----END " + label + "-----";
}

window.eccapp.util.arrayBufferToPem2 = function (arrayBuffer, label) {
    const binary = new Uint8Array(arrayBuffer);
    let base64 = '';
    for (let i = 0; i < binary.length; i++) {
        base64 += String.fromCharCode(binary[i]);
    }
    base64 = btoa(base64);
    
    const pemString = 
        "-----BEGIN " + label + "-----\n" +
        base64.match(/.{1,64}/g).join('\n') +
        "\n-----END " + label + "-----\n";
    return pemString;
};

window.eccapp.util.convertToPEM = function (keyData, label)
{
    const base64Key = eccapp.util.arrayBufferToBase64(keyData);
    const formattedKey = base64Key.match(/.{1,64}/g).join('\n');
    return "-----BEGIN " + label + "-----\n" + formattedKey + "\n-----END " + label + "-----\n";
}

window.eccapp.util.convertPrivateKeyToPKCS8 = function (secretKey)
{
	const oidEd25519 = [0x2B, 0x65, 0x70]; // 1.3.101.112 (Ed25519)

	const pkcs8Header = [
		0x30, 0x2E, // SEQUENCE, length 46
		0x02, 0x01, 0x00, // INTEGER, version 0
		0x30, 0x05, // SEQUENCE, length 5
		0x06, oidEd25519.length, ...oidEd25519, // OID, Ed25519
		0x04, 0x22, // OCTET STRING, length 34
		0x04, 0x20, // OCTET STRING, length 32
	];

	const pkcs8Key = new Uint8Array([
		...pkcs8Header,
		...secretKey.subarray(0, 32), // Ed25519 private key is first 32 bytes of secretKey
	]);

	return eccapp.util.arrayBufferToPem(pkcs8Key, "PRIVATE KEY");
}

window.eccapp.util.convertPublicKeyToSPKI = function (publicKey)
{
	const oidEd25519 = [0x2B, 0x65, 0x70]; // 1.3.101.112 (Ed25519)

	const spkiHeader = [
		0x30, 0x2A, // SEQUENCE, length 42
		0x30, 0x05, // SEQUENCE, length 5
		0x06, oidEd25519.length, ...oidEd25519, // OID, Ed25519
		0x03, 0x21, 0x00, // BIT STRING, length 33
	];

	const spkiKey = new Uint8Array([
		...spkiHeader,
		...publicKey, // Ed25519 public key
	]);

	return eccapp.util.arrayBufferToPem(spkiKey, "PUBLIC KEY");
}

window.eccapp.util.createCSR = function (keyPair, subject) {
    try {
        // OIDs
        const oidCommonName = new Uint8Array([0x55, 0x04, 0x03]);
        const oidCountryName = new Uint8Array([0x55, 0x04, 0x06]);
        const oidStateName = new Uint8Array([0x55, 0x04, 0x08]);
        const oidLocalityName = new Uint8Array([0x55, 0x04, 0x07]);
        const oidOrganizationName = new Uint8Array([0x55, 0x04, 0x0A]);
        const oidOrganizationalUnitName = new Uint8Array([0x55, 0x04, 0x0B]);
        const oidEd25519 = new Uint8Array([0x2B, 0x65, 0x70]);

        // Create subject
        const subjectAttributes = [
            { oid: oidCountryName, value: subject.countryName },
            { oid: oidStateName, value: subject.stateName },
            { oid: oidLocalityName, value: subject.locationName },
            { oid: oidOrganizationName, value: subject.organizationName },
            { oid: oidOrganizationalUnitName, value: subject.organizationalUnitName },
            { oid: oidCommonName, value: subject.commonName }
        ].filter(attr => attr.value); // Filter out any undefined values

        const subjectSequence = asn1Sequence(
            subjectAttributes.map(attr => 
                asn1Set([asn1Sequence([
                    asn1ObjectIdentifier(attr.oid),
                    asn1Utf8String(attr.value)
                ])])
            )
        );
        console.log('Subject Sequence:', eccapp.util.arrayBufferToHex(subjectSequence));

        // Create public key info
       const publicKeyInfo = asn1Sequence([
    asn1Sequence([asn1ObjectIdentifier(oidEd25519)]),
    new Uint8Array([0x03, 0x21, 0x00, ...keyPair.publicKey]) // BIT STRING
]);
        console.log('Public Key Info:', eccapp.util.arrayBufferToHex(publicKeyInfo));

        // Create CSR info
        const csrInfo = asn1Sequence([
            asn1Integer(0), // version
            subjectSequence,
            publicKeyInfo,
            asn1Sequence([]) // attributes (empty)
        ]);
        console.log('CSR Info:', eccapp.util.arrayBufferToHex(csrInfo));

        // Sign the CSR info
        const signature = nacl.sign.detached(csrInfo, keyPair.secretKey);
        console.log('Signature:', eccapp.util.arrayBufferToHex(signature));

        // Create the final CSR
        const csr = asn1Sequence([
            csrInfo,
            asn1Sequence([asn1ObjectIdentifier(oidEd25519)]),
            asn1OctetString(signature)
        ]);
        console.log('Final CSR:', eccapp.util.arrayBufferToHex(csr));

        return csr;
    } catch (error) {
        console.error('Error in createCSR:', error);
        throw error;
    }
};

window.eccapp.util.arrayBufferToHex = function (buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

window.eccapp.util.createSubjectDer = function (subject) {
    const oidCommonName = [0x55, 0x04, 0x03];
    const oidCountryName = [0x55, 0x04, 0x06];
    const oidOrganizationName = [0x55, 0x04, 0x0A];
    const oidOrganizationalUnitName = [0x55, 0x04, 0x0B];
    const oidLocationName = [0x55, 0x04, 0x07];
    const oidStateName = [0x55, 0x04, 0x08];

    const createAttributeTypeAndValue = (oid, value) => {
        const encodedValue = new TextEncoder().encode(value);
        return [
            0x30, encodedValue.length + oid.length + 4, // SEQUENCE
            0x06, oid.length, ...oid, // OID
            0x0C, encodedValue.length, ...encodedValue // UTF8String
        ];
    };

    const subjectAttributes = [
        createAttributeTypeAndValue(oidCountryName, subject.countryName),
        createAttributeTypeAndValue(oidStateName, subject.stateName),
        createAttributeTypeAndValue(oidLocationName, subject.locationName),
        createAttributeTypeAndValue(oidOrganizationName, subject.organizationName),
        createAttributeTypeAndValue(oidOrganizationalUnitName, subject.organizationalUnitName),
        createAttributeTypeAndValue(oidCommonName, subject.commonName)
    ].filter(attr => attr[2] > 0); // Remove any empty attributes

    const subjectSequence = new Uint8Array(subjectAttributes.flat());
    return new Uint8Array([0x30, ...eccapp.util.toLengthBytes(subjectSequence.length), ...subjectSequence]);
};

window.eccapp.util.createNameField = function (oid, value) {
    const valueBytes = new TextEncoder().encode(value);
    const oidEncoded = new Uint8Array([0x06, oid.length, ...oid]);
    const valueEncoded = new Uint8Array([0x13, valueBytes.length, ...valueBytes]);
    const sequenceLength = oidEncoded.length + valueEncoded.length;
    return new Uint8Array([
        0x31, sequenceLength + 2, // SET
        0x30, sequenceLength, // SEQUENCE
        ...oidEncoded,
        ...valueEncoded
    ]);
}

window.eccapp.util.createSPKI = function (publicKey)
{
	const oidEd25519 = [0x2B, 0x65, 0x70]; // OID for Ed25519

	return new Uint8Array([
		0x30, 0x2A, // SEQUENCE, length 42
		0x30, 0x05, // SEQUENCE, length 5
		0x06, oidEd25519.length, ...oidEd25519, // OID, Ed25519
		0x03, 0x21, 0x00, // BIT STRING, length 33
		...publicKey, // Ed25519 public key
	]);
}

//change
window.eccapp.util.toLengthBytes = function (len)
{
    if (len < 128) return [len];
    let lenBytes = [];
    while (len > 0) {
        lenBytes.unshift(len & 0xFF);
        len >>= 8;
    }
    return [0x80 | lenBytes.length, ...lenBytes];
}

window.eccapp.util.validateCSR = function (csr) {
    try {
        // Basic structure validation
        if (csr[0] !== 0x30) throw new Error("CSR doesn't start with SEQUENCE");
        
        // Add more validation steps here...

        console.log("CSR structure seems valid");
        return true;
    } catch (error) {
        console.error("CSR validation failed:", error);
        return false;
    }
}

window.eccapp.util.savePEMToFile = function (pemData)
{
    const blob = new Blob([pemData], { type: 'text/plain' });
    const link = document.createElement('a');

	const filename = 'member-' +
		eccapp.x509.data.info.firstname.toLowerCase() +
		'-' + eccapp.x509.data.info.lastname.toLowerCase() +
		'-' + eccapp.x509.data.info.code + '.pem';

    link.download = filename;
    link.href = window.URL.createObjectURL(blob);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

window.eccapp.util.saveCSRToFile = function (csrData)
{
    const blob = new Blob([csrData], { type: 'text/plain' });
    const link = document.createElement('a');

	const filename = 'member-' +
		eccapp.x509.data.info.firstname.toLowerCase() +
		'-' + eccapp.x509.data.info.lastname.toLowerCase() +
		'-' + eccapp.x509.data.info.code + '.csr';

    link.download = filename;
    link.href = window.URL.createObjectURL(blob);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// X509

window.eccapp.x509.generateKeys = function ()
{
	// Generate an Ed25519 key pair using tweetnacl.js
	eccapp.x509.data.keyPair = nacl.sign.keyPair();

	eccapp.x509.data.publicKey = eccapp.x509.data.keyPair.publicKey;
	eccapp.x509.data.privateKey = eccapp.x509.data.keyPair.secretKey;

	eccapp.x509.data.privateKeyPKCS8 = window.eccapp.util.convertPrivateKeyToPKCS8(eccapp.x509.data.keyPair.secretKey);
	console.log("Private Key PEM PKCS8:\n", eccapp.x509.data.privateKeyPKCS8);
}

window.eccapp.x509.convertKeysToPEM = function ()
{
	// Convert the keys to PEM format
	eccapp.x509.data.publicKeyPEM = eccapp.util.convertToPEM (eccapp.x509.data.publicKey, "PUBLIC KEY");
	eccapp.x509.data.privateKeyPEM = eccapp.util.convertToPEM(eccapp.x509.data.privateKey.subarray(0, 32), "PRIVATE KEY");

	console.log("Public Key PEM:\n", eccapp.x509.data.publicKeyPEM);
	console.log("Private Key PEM:\n", eccapp.x509.data.privateKeyPEM);
}

window.eccapp.x509.generatePEMs = function ()
{
	eccapp.x509.generateKeys();
	eccapp.x509.convertKeysToPEM();

	eccapp.x509.data.info =
	{
		firstname: document.getElementById("ecc-app-firstname").value,
		lastname: document.getElementById("ecc-app-lastname").value,
		code: document.getElementById("ecc-app-code").value,
		country: document.getElementById("ecc-app-country").value,
		state: document.getElementById("ecc-app-state").value,
		location: document.getElementById("ecc-app-location").value
	}

	console.log(eccapp.x509.data.info)

	eccapp.util.savePEMToFile(eccapp.x509.data.privateKeyPKCS8)
}

// Updated generateCSR function with more detailed logging
window.eccapp.x509.generateCSR = function () {
    try {
        if (!eccapp.x509.data || !eccapp.x509.data.keyPair) {
            throw new Error('Key pair not found. Please generate keys first.');
        }

        const keyPair = eccapp.x509.data.keyPair;
        console.log('Public Key:', eccapp.util.arrayBufferToHex(keyPair.publicKey));
        console.log('Private Key:', eccapp.util.arrayBufferToHex(keyPair.secretKey));

        const subject = {
            commonName: eccapp.x509.data.info.firstname.toLowerCase() + "." + eccapp.x509.data.info.lastname.toLowerCase() + "." + eccapp.x509.data.info.code + ".council.eastern.cardano",
            countryName: eccapp.x509.data.info.country,
            stateName: eccapp.x509.data.info.state,
            locationName: eccapp.x509.data.info.location,
            organizationName: "Eastern Cardano Council",
            organizationalUnitName: "Operations"
        };
        console.log('Subject:', subject);

        // Generate the CSR
        const csr = eccapp.util.createCSR(keyPair, subject);

        // Convert to PEM
        const csrPEM = eccapp.util.arrayBufferToPem2(csr, "CERTIFICATE REQUEST");

        // Save to file
        const blob = new Blob([csrPEM], { type: 'text/plain' });
        const link = document.createElement('a');
        const filename = 'member-' +
            eccapp.x509.data.info.firstname.toLowerCase() +
            '-' + eccapp.x509.data.info.lastname.toLowerCase() +
            '-' + eccapp.x509.data.info.code + '.csr';
        link.download = filename;
        link.href = window.URL.createObjectURL(blob);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        console.log("CSR generated and saved:", filename);
        console.log("CSR PEM:", csrPEM);
    } catch (error) {
        console.error('Error in generateCSR:', error);
        alert('Error generating CSR: ' + error.message);
    }
};

window.eccapp.init = function ()
{
	document.getElementById('ecc-app-create-x509-identity').addEventListener('click', function()
	{
		$('#ecc-app-create-x509-identity').addClass('disabled');
		window.eccapp.x509.generatePEMs();
		$('#ecc-app-create-x509-csr').removeClass('disabled');
		$('#ecc-app-create-x509-csr-view').removeClass('d-none');
	});

	document.getElementById('ecc-app-create-x509-csr').addEventListener('click', function()
	{
		$('#ecc-app-create-x509-csr').addClass('disabled');
		window.eccapp.x509b.generateCSR();
		//window.eccapp.x509.generateCSR();
	})
}

window.eccapp.init();

/*
async function createCertificate(publicKey, privateKey) {
    // Create a basic X.509 certificate
    const certificate = new pkijs.Certificate();

    // Set the certificate's version
    certificate.version = 2;

    // Set the serial number (arbitrary value here)
    certificate.serialNumber = new asn1js.Integer({ value: 1 });

    // Set the validity period
    certificate.notBefore.value = new Date(2024, 0, 1);
    certificate.notAfter.value = new Date(2025, 0, 1);

    // Set the issuer and subject (self-signed)
    certificate.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
        type: "2.5.4.3", // Common Name
        value: new asn1js.Utf8String({ value: "Test Certificate" })
    }));
    certificate.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
        type: "2.5.4.3", // Common Name
        value: new asn1js.Utf8String({ value: "Test Certificate" })
    }));

    // Import the public key
    await certificate.subjectPublicKeyInfo.importKey({
        kty: "OKP",
        crv: "Ed25519",
        x: publicKey
    });

    // Sign the certificate with the private key
    await certificate.sign(privateKey, "Ed25519");

    // Export the certificate as a PEM string
    const certDer = certificate.toSchema(true).toBER(false);
    const certPem = convertDERtoPEM(certDer, "CERTIFICATE");

    // Save the certificate as a PEM file
    savePEMToFile(certPem, "certificate.pem");

    console.log("Certificate saved to file.");
}

function convertDERtoPEM(derBuffer, label) {
    const base64String = window.btoa(String.fromCharCode(...new Uint8Array(derBuffer)));
    const pemString = `-----BEGIN ${label}-----\n${base64String.match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
    return pemString;
}

function savePEMToFile(pemData, fileName) {
    const blob = new Blob([pemData], { type: 'text/plain' });
    const link = document.createElement('a');
    link.download = fileName;
    link.href = window.URL.createObjectURL(blob);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Call the function to create and save the certificate
createCertificate(publicKey, privateKey);

*/