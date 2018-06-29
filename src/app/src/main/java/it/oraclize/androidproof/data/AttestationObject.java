package it.oraclize.androidproof.data;

import android.util.Base64;

import java.io.Serializable;

public class AttestationObject implements Serializable {
    public byte[]HTTPResponse;
    public byte[] requestID;
    public byte[] JWS_Header;
    public byte[] JWS_Payload;
    public byte[] JWS_Signature;
    public byte[] signature;

    public AttestationObject(byte[] _response, byte[] _requestID, String _JWS, byte[] _signature) {
        HTTPResponse = _response;
        requestID = _requestID;
        String[] jwsArray = _JWS.split("\\.");
        JWS_Header = Base64.decode(jwsArray[0], Base64.URL_SAFE);
        JWS_Payload = Base64.decode(jwsArray[1], Base64.URL_SAFE);
        JWS_Signature = Base64.decode(jwsArray[2], Base64.URL_SAFE);
        signature = _signature;
    }

}
