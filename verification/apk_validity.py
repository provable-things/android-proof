import base64
import hashlib
import sys

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc2315
import traceback
from cryptography import x509 
from cryptography.hazmat.backends import default_backend
from zipfile import ZipFile

def sha256(x):
    return hashlib.sha256(x).digest()

def custom_readlines(handle, line_separator="\n", chunk_size=64):
    buf = ""  # storage buffer
    while not handle.closed:  # while our handle is open
        data = handle.read(chunk_size)  # read `chunk_size` sized data from the passed handle
        if not data:  # no more data...
            break  # break away...
        buf += data  # add the collected data to the internal buffer
        if line_separator in buf:  # we've encountered a separator
            chunks = buf.split(line_separator)
            buf = chunks.pop()  # keep the last entry in our buffer
            for chunk in chunks:  # yield the rest
                yield chunk + line_separator
    if buf:
        yield buf  # return the last buffer if any

def verify_manifest(apkfile):
    source_zip = ZipFile(apkfile, 'r')
    source_entry_sorted_list = sorted(source_zip.namelist())
    if 'META-INF/MANIFEST.MF' in source_entry_sorted_list:
        manifest_handle = source_zip.open('META-INF/MANIFEST.MF', 'r')
        content = list(custom_readlines(manifest_handle, '\r\n\r\n'))
        manifest_handle.close()
        content = [ x.strip().split('SHA-256-Digest: ') for x in content]

        new_content = {}
        for x in content[1:]:
            path =  "".join(x[0].split())
            path = path.replace("Name:", "")
            new_content[path] = base64.b64decode(x[1])
        
        for path in new_content.keys():
            file_to_hash = source_zip.open(path, 'r').read()
            if new_content[path] != hashlib.sha256(file_to_hash).digest():
                raise Exception

def validate_signature_file(apkfile):

    source_zip = ZipFile(apkfile, 'r')
    # Compute SHA-256 hash of the MANIFEST.MF file    
    manifest_handle = source_zip.open('META-INF/MANIFEST.MF', 'r')
    manifest_content = manifest_handle.read()
    manifest_handle.close()
    manifest_hash = hashlib.sha256(manifest_content).digest()

    # Compare SHA-256 hash with MANIFEST.MF hash present 
    # in the signature file

    sig_handle = source_zip.open('META-INF/CERT.SF','r')
    
    sig_content = list(custom_readlines(sig_handle,'\r\n\r\n' ))
    
    manifest_hash_from_sig = sig_content[0].split('SHA-256-Digest-Manifest: ')[1].strip()
     
    if manifest_hash != base64.b64decode(manifest_hash_from_sig):
        raise Exception
    
    sig_content = [ x.strip().split('SHA-256-Digest: ') for x in sig_content]
   
    sig_entries = []
    
    for item in sig_content[1:]:
        sig_entries.append(base64.b64decode(item[1]))
       
    sig_handle.close()

    # Remove empty strings
    manifest_entries = filter(lambda x: x != '',
    manifest_content.split('\r\n\r\n')) 

    for i, entry in enumerate(manifest_entries[1:]):
        entry += "\r\n\r\n"
        if sig_entries[i] != sha256(entry):
            raise Exception



def verify_signature(apkfile):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    source_zip = ZipFile(apkfile, 'r')
    
    pad = padding.PKCS1v15()
    data = source_zip.open('META-INF/CERT.SF').read()
    signed_data = source_zip.open('META-INF/CERT.RSA', 'r').read()
    obj,rest = der_decoder.decode(signed_data, asn1Spec=rfc2315.ContentInfo(), decodeOpenTypes=True)
   
    signature =  str(obj['content']['signerInfos'][0]['encryptedDigest'])
    der_certificate = der_encoder.encode(obj['content']['certificates'][0]['certificate'])
    print 'Signing Certificate Digest: ' + base64.b64encode(sha256(der_certificate))
    cert = x509.load_der_x509_certificate(der_certificate, default_backend())
        
    cert.public_key().verify(signature, data, pad, hashes.SHA256())

def getApkHash(apkfile):
    file = open(apkfile)
    content = file.read()
    alg = hashlib.sha256()
    alg.update(content)
    print 'APK Hash: ' + base64.b64encode(alg.digest())


if __name__ == '__main__':
    try:
        verify_manifest(sys.argv[1])
        validate_signature_file(sys.argv[1])
        verify_signature(sys.argv[1])
        getApkHash(sys.argv[1])
    except:
        traceback.print_exc()


