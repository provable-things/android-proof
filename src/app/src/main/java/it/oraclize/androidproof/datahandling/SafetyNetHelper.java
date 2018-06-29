package it.oraclize.androidproof.datahandling;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.safetynet.SafetyNetClient;
import com.google.android.gms.safetynet.SafetyNetStatusCodes;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

import java.util.Arrays;

import it.oraclize.androidproof.Utils;
import it.oraclize.androidproof.data.SafetyNetResponse;

import static it.oraclize.androidproof.datahandling.FileWriterHelper.ERROR;
import static it.oraclize.androidproof.datahandling.FileWriterHelper.STATUS;

public class SafetyNetHelper implements SafetyNetInterface {

    private static final String TAG = "SafetyNetHelper";
    public static final int SAFETY_NET_API_UNKNOWN_ERROR = 1000;
    public static final int SAFETY_NET_API_EMPTY_RESPONSE = 1001;
    public static final int LOCAL_RESPONSE_VALIDATION_FAILED = 1003;
    public static final int GOOGLE_PLAY_SERVICES_NOT_AVAILABLE = 1004;

    private byte[] nonce;
    private String packageName;
    private String[] apkCertificateDigests;
    private String apkDigest;

    private SafetyNetWrapperCallback callback;

    private SafetyNetClient client;
    private FileWriterHelper filewriter;

    private Integer mTimeoutBetweenRetries;
    private Integer mRetriesMax;
    private Integer retriesCounter = 0;
    private String mApiKey;

    public interface SafetyNetWrapperCallback{
        void error(String errorType, String errorValue);
        void success(SafetyNetResponse response, String attestationResult);
    }

    public SafetyNetHelper (Context context, byte[] nonce, FileWriterHelper filewriter, Integer mTimeoutBetweenRetries, Integer mRetriesMax, String mApiKey) {
        this.nonce = nonce;
        client = SafetyNet.getClient(context);
        this.filewriter = filewriter;
        this.packageName = context.getPackageName();
        this.apkCertificateDigests = Utils.calcApkCertificateDigests(context);
        this.apkDigest = Utils.calcApkDigest(context);
        this.mTimeoutBetweenRetries = mTimeoutBetweenRetries;
        this.mRetriesMax = mRetriesMax;
        this.mApiKey = mApiKey;
    }

    /**
     * Call the SafetyNet test to check if this device profile /ROM has passed the CTS test
     * @param safetyNetWrapperCallback results and error handling
     */
    @Override
    public void requestTest(final SafetyNetWrapperCallback safetyNetWrapperCallback) {

        callback = safetyNetWrapperCallback;

        Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, mApiKey);
        task.addOnSuccessListener(mSuccessListener)
                .addOnFailureListener(mFailureListener);
    }

    private OnSuccessListener<SafetyNetApi.AttestationResponse> mSuccessListener = attestationResponse -> {
        final String jwsResult = attestationResponse.getJwsResult();
        if (!TextUtils.isEmpty(jwsResult)) {
            final SafetyNetResponse response = parseJsonWebSignature(jwsResult);

            if (validateSafetyNetResponsePayload(response)) {
                callback.success(response, jwsResult);
            } else {
                handleError(LOCAL_RESPONSE_VALIDATION_FAILED, jwsResult);
            }
        } else {
            handleError(SAFETY_NET_API_EMPTY_RESPONSE, "");
        }
        Log.d(TAG, "Success! SafetyNet result:\n" + jwsResult + "\n");
    };

    private OnFailureListener mFailureListener = exception -> {
        if (exception instanceof ApiException) {
            // An error with the Google Play Services API contains some additional details.
            ApiException apiException = (ApiException) exception;
            Log.e(TAG, "Error: " +
                    SafetyNetStatusCodes.getStatusCodeString(apiException.getStatusCode()) + ": " +
                    apiException.getStatusCode() + " = " + apiException.getMessage());
            if (apiException.getStatusCode() == SafetyNetStatusCodes.TIMEOUT) {
                handleError(SafetyNetStatusCodes.TIMEOUT, apiException.getMessage());
            } else if (apiException.getStatusCode() == SafetyNetStatusCodes.CANCELED) {
                handleError(apiException.getStatusCode(), apiException.getMessage());
            } else {
                Integer statusCode = apiException.getStatusCode();
                handleError(SAFETY_NET_API_UNKNOWN_ERROR, statusCode.toString());
            }
        } else {
            // A different, unknown type of error occurred.
            Log.e(TAG, "ERROR: " + exception.getClass().getCanonicalName() + ": " + exception.getMessage());
        }
    };


    boolean validateSafetyNetResponsePayload(SafetyNetResponse response) {
        if (response == null) {
            Log.e(TAG, "SafetyNetResponse is null.");
            return false;
        }

        final String requestNonceBase64 = Base64.encodeToString(nonce, Base64.DEFAULT).trim()
                .replace("\n","");

        if (!requestNonceBase64.equals(response.getNonce())){
            Log.e(TAG, "invalid nonce, expected = \"" + requestNonceBase64 + "\"");
            Log.e(TAG, "invalid nonce, response   = \"" + response.getNonce() + "\"");
            return false;
        }

        if (!packageName.equalsIgnoreCase(response.getApkPackageName())){
            Log.e(TAG, "invalid packageName, expected = \"" + packageName + "\"");
            Log.e(TAG, "invalid packageName, response = \"" + response.getApkPackageName() + "\"");
            return false;
        }

        if (!Arrays.equals(apkCertificateDigests,  response.getApkCertificateDigestSha256())){
            Log.e(TAG, "invalid apkCertificateDigest, local/expected = " + Arrays.asList(apkCertificateDigests));
            Log.e(TAG, "invalid apkCertificateDigest, response = " +  Arrays.asList(response.getApkCertificateDigestSha256()));
            return false;
        }

        if (!apkDigest.equals(response.getApkDigestSha256())){
            Log.e(TAG, "invalid ApkDigest, local/expected = \"" + apkDigest + "\"");
            Log.e(TAG, "invalid ApkDigest, response = \"" + response.getApkDigestSha256() + "\"");
            return false;
        }

        if (!response.isCtsProfileMatch()) {
            Log.e(TAG, "CtsProfileMatch is false");
            return false;
        }

        if (!response.isBasicIntegrity()) {
            Log.e(TAG, "BasicIntegrity is false");
            return false;
        }

        Log.d(TAG, response.toString());
        return true;
    }

    @Nullable SafetyNetResponse parseJsonWebSignature(@NonNull String jwsResult) {
        final String[] jwtParts = jwsResult.split("\\.");

        if (jwtParts.length == 3) {
            String decodedPayload = new String(Base64.decode(jwtParts[1], Base64.DEFAULT));

            return SafetyNetResponse.parse(decodedPayload);
        } else {
            return null;
        }
    }

    private void handleError(int errorCode, String errorValue) {

        switch (errorCode) {
            default:
            case SafetyNetHelper.SAFETY_NET_API_UNKNOWN_ERROR:
                Log.e(TAG, "SafetyNet Request: fail\n");
                callback.error("failed_safetynet_response", errorValue);
                retry();
                break;
            case SafetyNetHelper.SAFETY_NET_API_EMPTY_RESPONSE:
                Log.e(TAG, "SafetyNet Request: empty response\n");
                callback.error("empty_safetynet_response","");
                retry();
                break;
            case SafetyNetStatusCodes.CANCELED:
                Log.e(TAG, "SafetyNet Request: cancelled\n");
                callback.error("request cancelled", errorValue);
                retry();
                filewriter.appendToLogFile(ERROR, "handleError", "android_proof_failed", "");
                break;
            case SafetyNetHelper.GOOGLE_PLAY_SERVICES_NOT_AVAILABLE:
                Log.e(TAG, "SafetyNet Request: fail\n");
                filewriter.appendToLogFile(ERROR, "handleError", "android_proof_failed", "");
                callback.error("google play services not available", errorValue);
                break;
            case SafetyNetStatusCodes.TIMEOUT:
                Log.e(TAG, "SafetyNet Request: timeout\n");
                filewriter.appendToLogFile(ERROR, "handleError", "android_proof_failed", "");
                callback.error("safety_net_request_timeout", "");
                break;
            case SafetyNetHelper.LOCAL_RESPONSE_VALIDATION_FAILED:
                Log.e(TAG, "SafetyNet Request: success\n");
                Log.e(TAG, "Local response validation: fail\n");
                filewriter.appendToLogFile(ERROR, "handleError", "android_proof_failed", "");
                callback.error("local_response_validation_fail", errorValue);
                break;
        }
    }

    private void retry() {
        if ((retriesCounter < mRetriesMax)) {
            retriesCounter++;

            try {
                Log.d(TAG, "Retrying SafetyNet Request, waiting for " + mTimeoutBetweenRetries + "ms");
                Thread.sleep(mTimeoutBetweenRetries);
            } catch (InterruptedException e) {
                Log.e(TAG, e.getMessage());
                callback.error(e.getMessage(), "Timeout between retries failed");
                Thread.currentThread().interrupt();
            }

            Log.d(TAG, "SafetyNet Request retry: " + retriesCounter);
            filewriter.appendToLogFile(STATUS, "handleError", "safetynet_retry_number", retriesCounter.toString());

            Task<SafetyNetApi.AttestationResponse> task = client.attest(nonce, mApiKey);
            task.addOnSuccessListener(mSuccessListener)
                    .addOnFailureListener(mFailureListener);

        } else {
            Log.e(TAG, "Maximum retries reached with FAIL");
            filewriter.appendToLogFile(ERROR, "handleError", "android_proof_failed", "");
            callback.error("max_safety_net_retries_reached", retriesCounter.toString());
        }
    }
}
