# Android Proof

### Instruction

The application accepts as mandatory parameters:
* *url*: a URL (only HTTPS)
* *requestId*: a request ID, which can be the Oraclize query id
* *apiKey*: Android Device Verification API key for SafetyNet Attestation

Optionally, they can be also specified:
* *method*: the HTTP method used, e.g POST
* *data*: the data payload/parameters
* *readTimeout*: the URL query read timeout limit, default value is 12000ms
* *connectTimeout*: the URL query connect timeout limit, default value is 15000ms
* *requestProperty*: the request property for the URL query, default value is "application/x-www-form-urlencoded"
* *timeoutBetweenRetries*: if SafetyNet response fails, retry request after the elapsed timeout, default value is 5000ms
* *retriesMax*: if SafetyNet response fails, retry request a retriesMax number of times. Default value is 3


We start the application:

```bash
adb shell am start -n it.oraclize.androidproof/it.oraclize.androidproof.AndroidProofLauncher
```

We start the proof generation process

```bash
adb shell am broadcast -a it.oraclize.intent.Proof --es url "https://httpbin.org/post" --es requestID  $(date +%s) --es method "POST" --es requestProperty "application/json" --es data '\{"\"jsonrpc"\":"\"2.0"\"\,"\"method"\":"\"generateIntegers"\"\,"\"params"\":1}' --es readTimeout "1000" --es connectTimeout "1000" --es timeoutBetweenRetries "1000" --es retriesMax "5" --es apiKey "$requestID"
```

We retrieve the proof from the device:
```bash
adb pull /storage/emulated/0/Android/data/it.oraclize.androidproof/files/Documents/AndroiProof_$requestID.proof
```

We retrieve the certificate chain from the device:

```bash
adb pull /storage/emulated/0/Android/data/it.oraclize.androidproof/files/Documents/AndroidProof.chain
```


## Rationale and Overview of Design

The Android Proof leverages the security guarantees offered by Android devices shipped with 
Android Oreo and newer versions through the use of Software and Hardware Attestation for the 
provision of a secure and auditable environment whereby authenticable data can be fetched.

The Android Proof is based on a service application, which is running on a physical Android device 
stored in our datacenter connected to the backend. 
These devices have a Trusted Execution Environment which enables developers to generate a certificate 
chain from a key residing in the Android Hardware Keystore. The certificate chain has information 
needed to prove that the key has been generated from the KeyStore and is retrieved and sent to Oraclize’s infrastructure. 

The full chain of certificates must be verified against publicly available Google-owned Certificate Revocation Lists.
If this claim holds true, when a query is asked with AndroidProof, Oraclize backend sends the query URL 
(and other parameters) to the service running on the phone through a USB connection. The service 
receives the parameters via ADB and it downloads the provided URL response via HTTPS (only). 

Google Play Services offers an API called SafetyNet to provide Software Attestation. This API
provides Android developers a way to discover if the device their app is running
on has been rooted or it is an unknown, possibly malicious device. The API
uses proprietary mechanism, with Google promising that it will keep it updated to
their best knowledge of new vulnerabilities.

We send the HTTPS response, the signature from the hardware-backed Keystore and the request ID 
as the nonce for the SafetyNet request. The API requires a Google API key that must be generated on their platform 
and passed via USB to the app.

The response is an AttestationResponse with a JWS (JSON Web Signature) object composed by
three parts, separated by a point:
* An header: the certificate chain encoded in BASE64_URLSAFE
* A payload: the SafetyNet response encoded in BASE64_URLSAFE
* The signature: a 256-byte RSA_PCKS_V1.5 signature encoded in BASE64_URLSAFE, obtained signing the output of SHA256(header.payload) (both in encoded version).

The payload, which is the SafetyNet result contains:
* nonce: a random token generated in a cryptographically secure manner.
* package_name
* timestamp
* apkCertificateDigestSha256: sha256 of certificate used to sign app
* apkDigestSha256: SHA256 of apk
* ctsProfileMatch: Google compatibility test (true/false)
* basicIntegrity: other device integrity tests besides Google's CTS (true/false)

After a quick verification against the locally computed value, we send the HTTP response and 
attestation response via ADB to Oraclize backend and then to the querying contract, which can now verify the authenticity
of the signature using the public key contained in the first certificate of the
header certificate chain. The SHA256 of the apk generated from our deterministic build process permits 
everyone to verify that the open-sourced app code is effectively the one generating the proof.
 
You can get more information on the Android Proof verification process on our guide [Advanced Verification](verification/README.md) or use our 
 [Proof Verification Tool](https://github.com/oraclize/proof-verification-tool) to verify the proof.