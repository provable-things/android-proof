from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import *
from OpenSSL import crypto
from pyasn1.type import univ, namedval, constraint, tag, namedtype
from pyasn1.codec.ber import encoder, decoder
import hashlib
import base64
import json
import cbor2
import requests
import argparse

try:
    from termcolor import colored
except:
    def colored(str, col):
        return ''.join(str)

class VerifiedBootState(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Verified', 0),
        ('SelfSigned', 1),
        ('Unverified', 2),
        ('Failed', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + \
                constraint.SingleValueConstraint(0, 1, 2, 3)


class SecurityLevel(univ.Enumerated):
    namedValues = namedval.NamedValues(
    ('Software', 0),
    ('TrustedEnvironment', 1),
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + \
                constraint.SingleValueConstraint(0, 1)

class Purpose(univ.SetOf):
    componentType = univ.Integer()

class Digest(univ.SetOf):
    componentType = univ.Integer()

class Padding(univ.SetOf):
    componentType = univ.Integer()

class RootOfTrust(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('verifiedBootKey', univ.OctetString()),
        namedtype.NamedType('deviceLocked', univ.Boolean()),
        namedtype.NamedType('verifiedBootState', VerifiedBootState())
    )

class AuthorizationList(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('purpose', Purpose().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    1
                ))
            ),
            namedtype.OptionalNamedType('algorithm', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    2
                ))
            ),
            namedtype.OptionalNamedType('keySize', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    3
                ))
            ),
            namedtype.OptionalNamedType('digest', Digest().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    5
                ))
            ),
            namedtype.OptionalNamedType('padding', Padding().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    6
                ))
            ),
            namedtype.OptionalNamedType('ecCurve', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    10
                ))
            ),
            namedtype.OptionalNamedType('rsaPublicExponent', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    200
                ))
            ),
            namedtype.OptionalNamedType('activeDateTime', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    400
                ))
            ),
            namedtype.OptionalNamedType('originationExpireDateTime', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    401
                ))
            ),
            namedtype.OptionalNamedType('usageExpireDateTime', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    402
                ))
            ),
            namedtype.OptionalNamedType('noAuthRequired', univ.Null().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    503
                ))
            ),
            namedtype.OptionalNamedType('userAuthType', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    504
                ))
            ),
            namedtype.OptionalNamedType('authTimeout', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    505
                ))
            ),
            namedtype.OptionalNamedType('allowWhileOnBody', univ.Null().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    506
                ))
            ),
            namedtype.OptionalNamedType('allApplications', univ.Null().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    600
                ))
            ),
            namedtype.OptionalNamedType('applicationId', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    601
                ))
            ),
            namedtype.OptionalNamedType('creationDateTime', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    701
                ))
            ),
            namedtype.OptionalNamedType('origin', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    702
                ))
            ),
            namedtype.OptionalNamedType('rollbackResistant', univ.Null().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    703
                ))
            ),
            namedtype.OptionalNamedType('rootOfTrust', RootOfTrust().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    704
                ))
            ),
            namedtype.OptionalNamedType('osVersion', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    705
                ))
            ),
            namedtype.OptionalNamedType('osPatchLevel', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    706
                ))
            ),
            namedtype.OptionalNamedType('attestationChallenge', univ.Integer().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    708
                ))
            ),
            namedtype.OptionalNamedType('attestationApplicationId', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    709
                ))
            ),
            namedtype.OptionalNamedType('attestationIdBrand', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    710
                ))
            ),
            namedtype.OptionalNamedType('attestationIdDevice', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    711
                ))
            ),
            namedtype.OptionalNamedType('attestationIdProduct', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    712
                ))
            ),
            namedtype.OptionalNamedType('attestationIdSerial', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    713
                ))
            ),
            namedtype.OptionalNamedType('attestationIdImei', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    714
                ))
            ),
            namedtype.OptionalNamedType('attestationIdMeid', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    715
                ))
            ),
            namedtype.OptionalNamedType('attestationIdManufacturer', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    716
                ))
            ),
            namedtype.OptionalNamedType('attestationIdModel', univ.OctetString().subtype(
                explicitTag = tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    717
                ))
            )
    )

class KeyDescription(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('attestationVersion', univ.Integer()),
            namedtype.NamedType('attestationSecurityLevel', SecurityLevel()),
            namedtype.NamedType('keymasterVersion', univ.Integer()),
            namedtype.NamedType('keymasterSecurityLevel', SecurityLevel()),
            namedtype.NamedType('attestationChallenge', univ.OctetString()),
            namedtype.NamedType('reserved', univ.OctetString()),
            namedtype.NamedType('softwareEnforced', AuthorizationList()),
            namedtype.NamedType('teeEnforced', AuthorizationList())
        )



class AttestationPackageInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('packageName', univ.OctetString()),
            namedtype.NamedType('version', univ.Integer())
    )

class AttestationApplicationId(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('packageInfos', univ.SetOf(componentType=AttestationPackageInfo())),
            namedtype.NamedType('signatureDigests', univ.SetOf(componentType=univ.OctetString()))
    )

def create_pem_encoded_cert(text):
    out = ""
    for i in range(0,len(text),64):
        out += text[i:i+64] + "\n"
    return "-----BEGIN CERTIFICATE-----\n" + out + "-----END CERTIFICATE-----"

def b64decode(text):
    not_padded = True
    while not_padded:
        try:
            text_decoded = base64.urlsafe_b64decode(text)
            not_padded = False
        except TypeError:
            text = text + "="
    return text_decoded

def get_android_proof(filename):
    attestation_result_file = open(filename, "r")
    result_array = attestation_result_file.read()
    #Removing first 3-bytes: first byte indicates proof type, second and third
    #proof version
    version = result_array[2].encode('hex')
    print "\nThis file is an Android Proof Version " + str(int(version))
    json_android_proof = result_array[3:]
    return json_android_proof

def extract_google_cert(decoded_header):
    header_dictionary = json.loads(decoded_header)
    google_cert_chain = header_dictionary['x5c']
    google_cert = create_pem_encoded_cert(str(google_cert_chain[0]))
    google_cert2 = create_pem_encoded_cert(str(google_cert_chain[1]))
    sn_root = x509.load_pem_x509_certificate(google_cert2, default_backend())
    return x509.load_pem_x509_certificate(google_cert, default_backend())

def verify_jws_signature(decoded_header,encoded_header,encoded_payload, decoded_signature):
    google_cert = extract_google_cert(decoded_header)
    input_data = encoded_header + "." + encoded_payload
    if crypto.verify(google_cert, decoded_signature, input_data, 'sha256') is None:
        return True
    else:
        return False

def verify_response_signature(leaf,response,response_signature):
    import traceback
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    cert = x509.load_der_x509_certificate(leaf, default_backend())
    try:
        pad = padding.PKCS1v15()
        cert.public_key().verify(response_signature, response, pad, hashes.SHA256())
        return True
    except:
        traceback.print_exc()
        return False

def verify_jws_payload(decoded_header, decoded_payload, requestID, response, response_signature, apk_hash, apk_cert_hash, user_request_timestamp = 0):
    decoded_payload = json.loads(decoded_payload)
    m = hashlib.sha256()
    m.update(response)
    m.update(response_signature)
    m.update(requestID)
    nonce = m.digest()
    verification_counter = 0
    print "\n 2. JWS Payload Verification"
    if decoded_payload['nonce'] == base64.b64encode(nonce):
       print "   * Does nonce match expected value? " + colored('[Yes]', 'green')
       verification_counter+=1
    else:
       print "   * Does nonce match expected value? " + colored('[No]', 'red')

    if decoded_payload['timestampMs'] > user_request_timestamp:
        print "   * Is request timestamp correct?: " + colored('[Yes]', 'green')
        verification_counter+=1
    else:
        print "   * Is request timestamp correct?: " + colored('No]', 'red')

    if decoded_payload['apkPackageName'] == "it.oraclize.androidproof":
        print "   * Does apkPackageName match expected value? " + colored('[Yes]', 'green')
        verification_counter+=1
    else:
        print "   * Does apkPackageName match expected value? " + colored('[No]', 'red')
    
    print decoded_payload['apkDigestSha256']
    if decoded_payload['apkDigestSha256'] == apk_hash:
        print "   * Does apkDigestSha256 match expected value? " + colored('[Yes]', 'green')
        verification_counter+=1
    else:
        print "   * Does apkDigestSha256 match expected value? " + colored('[No]', 'red')

    if decoded_payload['apkCertificateDigestSha256'][0] == apk_cert_hash:
        print "   * Does apkCertificateDigestSha256 match expected value? " + colored('[Yes]', 'green')
        verification_counter+=1
    else:
         print "   * Does apkCertificateDigestSha256 match expcted value? " + colored('[No]', 'red')

    if decoded_payload['ctsProfileMatch']:
        print "   * Is cstProfileMatch true? " + colored('[Yes]', 'green')
        verification_counter+=1
    else:
        print "   * Is cstProfileMatch true? "  + colored('[No]', 'green')

    if decoded_payload['basicIntegrity']:
        print "   * Is basicIntegrity true? " + colored('[Yes]', 'green')
        verification_counter+=1
    else:
        print "   * Is basicIntegrity true? " + colored('[No]', 'red')

    if verification_counter == 7:
        return True
    else:
        return False


def verify_against_google_api(google_cert, jws, google_api_key):
    cert_common_name = google_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    attest = cert_common_name[0].value
    url = "https://www.googleapis.com/androidcheck/v1/attestations/verify?key=" + google_api_key
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    data = { "signedAttestation" : jws}
    google_verification_request = requests.post(url, data = json.dumps(data), headers = headers)
    google_verification_response = google_verification_request.json()

    if google_verification_response['isValidSignature'] and attest == "attest.android.com":
        return True
    else:
        return False


def get_attestation_crl(site):
    print site
    r = requests.get(site + '.crl')
    print r
    attestation_crl = x509.load_der_x509_crl(r.content, default_backend())
    return attestation_crl

def get_google_crl():
    r = requests.get('https://pki.google.com/GIAG2.crl')
    crl_der = r.content
    google_crl = x509.load_der_x509_crl(crl_der, default_backend())
    return google_crl

def verify_revoked(decoded_header):
    header_dictionary = json.loads(decoded_header)
    google_cert_chain = header_dictionary['x5c']
    leaf_cert_pem_encoded = create_pem_encoded_cert(str(google_cert_chain[0]))
    leaf_cert = x509.load_pem_x509_certificate(leaf_cert_pem_encoded, default_backend())
    root_cert_pem_encoded = create_pem_encoded_cert(str(google_cert_chain[1]))
    root_cert = x509.load_pem_x509_certificate(root_cert_pem_encoded, default_backend())
    crl = get_google_crl()
    for revoked_cert in crl:
        if revoked_cert.serial_number == leaf_cert.serial_number or \
            revoked_cert.serial_number == root_cert.serial_number:
            return False
    return True

def verify(filename, google_api_key, apk_hash, apk_cert_hash, hw_attestation_file):
    android_proof = get_android_proof(filename)
    cbor_android_proof = cbor2.loads(android_proof)
    cbor_chain_file = open(hw_attestation_file, 'r')
    cbor_chain = cbor_chain_file.read()
    chain = cbor2.loads(cbor_chain)
    decoded_header = cbor_android_proof['JWS_Header']
    decoded_signature = cbor_android_proof['JWS_Signature']
    decoded_payload = cbor_android_proof['JWS_Payload']

    leaf = chain['leaf']
    intermediate = chain['intermediate']
    root = chain['root']
    certificate_chain = [leaf, intermediate, root]
    encoded_header =  base64.urlsafe_b64encode(cbor_android_proof['JWS_Header'])
    encoded_payload =  base64.urlsafe_b64encode(cbor_android_proof['JWS_Payload'])
    encoded_signature = base64.urlsafe_b64encode(cbor_android_proof['JWS_Signature'])
    encoded_header = encoded_header.replace("=","")
    encoded_payload = encoded_payload.replace("=","")
    encoded_signature = encoded_signature.replace("=","")

    jws_array = [encoded_header, encoded_payload, encoded_signature]
    point = '.'
    jws = point.join(jws_array)
    requestID = str(cbor_android_proof['requestID'])
    response = str(cbor_android_proof['HTTPResponse'])
    response_signature = str(cbor_android_proof['signature'])
    google_cert = extract_google_cert(decoded_header)
    verified = True

    if verify_jws_signature(decoded_header, encoded_header, encoded_payload, decoded_signature):
        print "\n 1. JWS Signature Verification: " + colored('[Passed]', 'green')
    else:
        verified = False
        print "\n 1. JWS Signature Verification: " + colored('[Failed]', 'red')

    if verify_jws_payload(decoded_header, decoded_payload, requestID, response, response_signature, apk_hash, apk_cert_hash,0):
        print "   Result: " + colored('[Passed]', 'green')
    else:
        verified = False
        print "   Result  " + colored('[Failed]', 'red')

    # #Third verification: verify response against google server
    if verify_against_google_api(google_cert, jws, google_api_key):
        print "\n 3. JWS Authenticity Verification: " + colored('[Passed]', 'green')
    else:
        verified = False
        print "\n 3. JWS Authenticity Verification: " + colored('[Failed]', 'red')

    if verify_hardware_attestation_chain(certificate_chain):
        print"\n 4. Hardware Attestation Certificate Chain Verification: " + colored('[Passed]', 'green')
    else:
        verified = False
        print"\n 4. Hardware Attestation Certificate Chain Verification: " + colored('[Failed]', 'red')

    if check_hardware_attestation_object(leaf):
        print"\n 5. Hardware Attestation Parameters Verification " + colored('[Passed]', 'green')
    else:
        verified = False
        print"\n 5. Hardware Attestation Parameters Verification " + colored('[Failed]', 'red')

    if verify_revoked(decoded_header):
        print "\n 6. Verify Certificates against Revocation Lists "  + colored('[Passed]', 'green')
    else:
        verified = False
        print "\n 6. Verify Certificates against Revocation Lists "  + colored('[Failed]', 'red')
    
    if verify_response_signature(leaf, response, response_signature):
        print "\n 7. Verify HTTP Response Signature "  + colored('[Passed]', 'green')
    else:
        verified = False
        print "\n 7. Verify HTTP Response Signature "  + colored('[Failed]', 'red')

    return response if verified else None


def check_hardware_attestation_object(leaf):
    cert = x509.load_der_x509_certificate(leaf, default_backend())
    cert_hw_attestation = cert.extensions[1].value.value
    attestation_obj = decoder.decode(cert_hw_attestation, asn1Spec=KeyDescription())[0]
    obj = str(attestation_obj['softwareEnforced']['attestationApplicationId'])
    # print obj.encode('hex')
    # print decoder.decode(obj, asn1Spec=AttestationApplicationId())[0]
    if str(attestation_obj['attestationSecurityLevel']) == 'TrustedEnvironment':
        print"   * Is key attestation hardware enforced? " + colored('[Yes]', 'green')
    else:
        print"   * Is key attestation hardware enforced? " + colored('[Pending]', 'yellow')

    if attestation_obj['keymasterVersion'] == 3:
        print"   * Is keymaster at latest version? " + colored('[Yes]', 'green')
    else:
        print"   * Is keymaster at latest version? " + colored('[Pending]', 'yellow')

    if attestation_obj['keymasterSecurityLevel'] == 1:
        print"   * Is key hardware enforced? " + colored('[Yes]', 'green')
    else:
        print"   * Is key hardware enforced? " + colored('[No]', 'red')

    if attestation_obj['attestationChallenge'] == 'Oraclize':
        print"   * Is attestation challenge correct? " + colored('[Yes]', 'green')
    else:
        print"   * Is attestation challenge correct? " + colored('[No]', 'red')

    if attestation_obj['teeEnforced']['purpose'][0] == 2:
        print"   * Is key only purpose signing? " + colored('[Yes]', 'green')
    else:
        print"   * Is key only purpose signing " + colored('[No]', 'red')

    if attestation_obj['teeEnforced']['algorithm'] == 1:
        print"   * Is key algorithm RSA? " + colored('[Yes]', 'green')
    else:
        print"   * Is key algorithm RSA? " + colored('[No]', 'red')

    if attestation_obj['teeEnforced']['digest'][0] == 4:
        print"   * Is key digest SHA256? " + colored('[Yes]', 'green')
    else:
        print"   * Is key digest SHA256? " + colored('[No]', 'red')

    '''
    if attestation_obj['teeEnforced']['ecCurve'] == 1:
        print"   * Is key EC curve choice NIST-256P? " + colored('[Yes]', 'green')
    else:
        print"   * Is key EC curve choice NIST-256P?" + colored('[No]', 'red')
    '''
    if attestation_obj['teeEnforced']['origin'] == 0:
        print"   * Is key generated in TEE? " + colored('[Yes]', 'green')
    else:
        print"   * Is key generated in TEE? " + colored('[No]', 'red')

    return True

def verify_hardware_attestation_chain(certificate_chain):
    import traceback
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    #points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    #for point in points.value:
    #    print get_attestation_crl(str(point.full_name[0].value))
   
    leaf = x509.load_der_x509_certificate(certificate_chain[0], default_backend())
    inter = x509.load_der_x509_certificate(certificate_chain[1], default_backend())
    attestation_root = x509.load_der_x509_certificate(certificate_chain[2], default_backend())
    google_root = x509.load_pem_x509_certificate(open('google_root.pem','r').read(), default_backend()) 
    try:
        pad = padding.PKCS1v15()
        inter.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, pad, hashes.SHA256())
        attestation_root.public_key().verify(inter.signature, inter.tbs_certificate_bytes, pad, hashes.SHA256())
        google_root.public_key().verify(attestation_root.signature, attestation_root.tbs_certificate_bytes, pad, hashes.SHA256())
        google_root.public_key().verify(google_root.signature, google_root.tbs_certificate_bytes, pad, hashes.SHA256())
        return True
    except:
        traceback.print_exc()
        return False 


def apk_verify(apk):
    # parse apk
    # extract signing certificate from apk
    # extract signature
    # calculate merkle digest of apk
    return certificate, signature, digest  

def main():
    parser = argparse.ArgumentParser(description='Verify Oraclize Android Proof')

    parser.add_argument('--filename',
                        '-f',
                        action = 'store',
                        dest = 'filename',
                        help = 'Proof Filename')

    parser.add_argument('--google_api_key',
                        '-k',
                        action = 'store',
                        dest = 'key',
                        help = 'Google API Verification Key')

    parser.add_argument('--apk_hash',
                        '-ah',
                        action = 'store',
                        dest = 'apk_hash',
                        help = 'Sha256 Digest in Base64 of Application Package')

    parser.add_argument('--apk_cert_hash',
                        '-ach',
                        action = 'store',
                        dest = 'apk_cert_hash',
                        help = 'Certificate Sha256 Digest in Base64 of the Application Package Signing Certificate')


    parser.add_argument('--hardware-attestation',
                        '-hwa',
                        action = 'store',
                        dest = 'hw_attestation_file',
                        help = 'File containing certificate chain of hardware attested key')

    args = parser.parse_args()

    if args.filename and args.key and args.apk_hash and args.apk_cert_hash and args.hw_attestation_file:
        verify(args.filename, args.key, args.apk_hash, args.apk_cert_hash, args.hw_attestation_file)
    else:
        print parser.print_help()

if __name__ == "__main__":
    main()
