package it.oraclize.androidproof;

import android.app.IntentService;
import android.content.Intent;

import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;

import org.apache.commons.codec.DecoderException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import org.apache.commons.codec.binary.Hex;

import it.oraclize.androidproof.data.SafetyNetResponse;
import it.oraclize.androidproof.datahandling.AndroidProofWriter;
import it.oraclize.androidproof.datahandling.FileWriterHelper;
import it.oraclize.androidproof.datahandling.NetworkDataSource;
import it.oraclize.androidproof.datahandling.SafetyNetHelper;
import it.oraclize.androidproof.datahandling.SafetyNetInterface;

public class AndroidProofService extends IntentService {
    private static final String TAG = "AndroidProofService";
    private static final String STATUS = "Status";
    private static final String ERROR = "Error";
    private static final String keyAlias = "oraclize";

    private SafetyNetInterface safetyNetHelper;
    private NetworkDataSource dataSource;

    private byte[] mResponse;
    private byte[] mSignature;
    private byte[] mRequestID;

    private Long startTime;
    private FileWriterHelper filewriter;

    public AndroidProofService() {
        super(AndroidProofService.class.getName());
    }


    /**
     * Fetches an entire HTML server response from an HTTP over TLS connection and signs with the Keystore.
     *
     * @param workIntent
     */
    @Override
    protected void onHandleIntent(Intent workIntent) {

        startTime = System.currentTimeMillis();

        String url = workIntent.getStringExtra("url");
        String method = workIntent.getStringExtra("method");
        String dataPayload = workIntent.getStringExtra("data");
        String requestProperty = workIntent.getStringExtra("requestProperty");
        Integer readTimeOut = workIntent.getIntExtra("readTimeout", 12000);
        Integer connectTimeOut = workIntent.getIntExtra("connectTimeout", 15000);

        final String requestID = workIntent.getStringExtra("requestID");
        Integer timeoutBetweenRetries = workIntent.getIntExtra("timeoutBetweenRetries", 5000);
        Integer retriesMax = workIntent.getIntExtra("retriesMax", 3);
        String apiKey = workIntent.getStringExtra("apiKey");

        try {

            mRequestID = Hex.decodeHex(requestID.toCharArray());

            if (url == null || mRequestID == null || apiKey == null) {
                throw new Exception("Null arguments");
            }

            if (requestProperty == null)
                requestProperty = "application/x-www-form-urlencoded";

            filewriter = new FileWriterHelper(getApplicationContext());
            filewriter.createFile("AndroidProof_" + requestID + ".log");

            String receivedRequest =
                    " URL: " + url
                            + "\n requestID: " + requestID
                            + "\n method: " + method
                            + "\n dataPayload: " + dataPayload
                            + "\n requestProperty: " + requestProperty
                            + "\n Connection Timeout: " + connectTimeOut
                            + "\n Read Timeout: " + readTimeOut
                            + "\n Max Number of SafetyNet Retries: " + retriesMax
                            + "\n Max Timeout between retries: " + timeoutBetweenRetries;

            Log.d(TAG, "Received request:\n" + receivedRequest);
            filewriter.appendToLogFile( STATUS, "onHandleIntent", "request", receivedRequest);

            dataSource = new NetworkDataSource(url, method, dataPayload, requestProperty, readTimeOut, connectTimeOut, filewriter);

            mResponse = dataSource.fetchPage();

            mSignature = signResponse(mResponse);

            byte[] nonce = getNonce(mResponse, mSignature, mRequestID);

            safetyNetHelper = new SafetyNetHelper(getApplicationContext(), nonce, filewriter, timeoutBetweenRetries, retriesMax, apiKey);
            // If a device doesn't have Google Play services installed, or doesn't have it up to date,
            // using the SafetyNet Attestation API may lead to the app becoming unresponsive or crashing.
            // Minimum recommended is Google Play services 11.0.0
            if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)
                    == ConnectionResult.SUCCESS) {
                safetyNetHelper.requestTest(new SafetyNetHelper.SafetyNetWrapperCallback() {
                    @Override
                    public void error(String errorType, String errorValue) {
                        Log.e(TAG, "requestTest returned error:" + errorType);
                        filewriter.appendToLogFile(ERROR, TAG, errorType, errorValue);
                    }

                    @Override
                    public void success(SafetyNetResponse response, String attestationResult) {
                        filewriter.appendToLogFile(STATUS, TAG, "successful_safetynet_response", response.toString());

                        AndroidProofWriter proofWriter = new AndroidProofWriter(getApplicationContext());
                        proofWriter.createFile("AndroidProof_" + requestID + ".proof");
                        proofWriter.writeToProofFile(attestationResult, mResponse, mSignature, mRequestID, startTime);
                        safetyNetHelper = null;
                    }
                });
            } else {
                Log.e(TAG, "google play services not available: fail\n");
                filewriter.appendToLogFile(ERROR, "handleError", "google play services not available", "");
                filewriter.appendToLogFile(ERROR, "handleError", "android_proof_failed", "");
            }

        } catch (DecoderException e) {
            filewriter.appendToLogFile(ERROR, "onHandleIntent", "error_message", e.getMessage());
            Log.e(TAG, ERROR, e);
        } catch (Exception e) {
            filewriter.appendToLogFile(ERROR, "onHandleIntent", "error_message", e.getMessage());
            Log.e(TAG, ERROR, e);
        }

    }

    /**
     * The method extract the first certificate from the certificate chain attesting that we are on a TEE
     * backed device, and that the device hasn't been rooted. We return the certificate.
     **/
    private byte[] signResponse(byte[] responseBodyBytes) throws Exception {

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(keyAlias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return new byte[0];
        }
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
        s.update(responseBodyBytes);

        return s.sign();
    }

    private byte[] getNonce(byte[] mResponse, byte[] mSignature, byte[] requestID) {
        Log.d(TAG, "Setting nonce");
        ByteArrayOutputStream nonceStream = new ByteArrayOutputStream();
        try {
            nonceStream.write(mResponse);
            nonceStream.write(mSignature);
            nonceStream.write(requestID);

            byte[] nonceBytes = nonceStream.toByteArray();
            MessageDigest digest = MessageDigest.getInstance("SHA256");
            digest.update(nonceBytes);

            return digest.digest();
        } catch (IOException e) {
            filewriter.appendToLogFile(ERROR,  "onHandleIntent", "error_message", e.getMessage());
            Log.e(TAG, ERROR, e);
            e.printStackTrace();
            return new byte[0];
        } catch (NoSuchAlgorithmException e) {
            filewriter.appendToLogFile(ERROR, "onHandleIntent", "error_message", e.getMessage());
            Log.e(TAG, ERROR, e);
            e.printStackTrace();
            return new byte[0];
        }
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy");
        super.onDestroy();
    }
}


