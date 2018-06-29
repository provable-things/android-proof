package it.oraclize.androidproof.data;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;

public class SafetyNetResponse {

    private static final String TAG = "AndroidProof";
    private String nonce;
    private long timestampMs;
    private String apkPackageName;
    private String[] apkCertificateDigestSha256;
    private String extension;
    private String apkDigestSha256;
    private boolean ctsProfileMatch;
    private boolean basicIntegrity;

    private SafetyNetResponse(){}

    /**
     *
     * @return BASE64 encoded
     */
    public String getNonce() {
        return nonce;
    }

    public long getTimestampMs() {
        return timestampMs;
    }

    public String getApkPackageName() {
        return apkPackageName;
    }

    /**
     *
     * @return BASE64 encoded
     */
    public String[] getApkCertificateDigestSha256() {
        return apkCertificateDigestSha256;
    }

    /**
     *
     * @return BASE64 encoded
     */
    public String getApkDigestSha256() {
        return apkDigestSha256;
    }


    public boolean isCtsProfileMatch() {
        return ctsProfileMatch;
    }

    public boolean isBasicIntegrity() {
        return basicIntegrity;
    }

    /**
     * Parse the JSON string into populated SafetyNetResponse object
     * @param decodedJWTPayload JSON String (always a json string according to JWT spec)
     * @return populated SafetyNetResponse
     */

    public static @Nullable SafetyNetResponse parse(@NonNull String decodedJWTPayload) {

        SafetyNetResponse response = new SafetyNetResponse();
        try {
            JSONObject root = new JSONObject(decodedJWTPayload);
            if (root.has("nonce")) {
                response.nonce = root.getString("nonce");
            }

            if (root.has("apkCertificateDigestSha256")) {
                JSONArray jsonArray = root.getJSONArray("apkCertificateDigestSha256");
                if (jsonArray != null) {
                    String[] certDigests = new String[jsonArray.length()];
                    for (int i = 0; i < jsonArray.length(); i++) {
                        certDigests[i] = jsonArray.getString(i);
                    }
                    response.apkCertificateDigestSha256 = certDigests;
                }
            }

            if (root.has("apkDigestSha256")) {
                response.apkDigestSha256 = root.getString("apkDigestSha256");
            }

            if (root.has("apkPackageName")) {
                response.apkPackageName = root.getString("apkPackageName");
            }

            if (root.has("ctsProfileMatch")) {
                response.ctsProfileMatch = root.getBoolean("ctsProfileMatch");
            }

            if (root.has("timestampMs")) {
                response.timestampMs = root.getLong("timestampMs");
            }

            if (root.has("extension")) {
                response.extension = root.getString("extension");
            }

            if (root.has("basicIntegrity")) {
                response.basicIntegrity = root.getBoolean("basicIntegrity");
            }

            return response;
        } catch (JSONException e) {
            Log.e(TAG, "problem parsing decodedJWTPayload:"+ e.getMessage(), e);

        }
        return null;
    }

    @Override
    public String toString() {
        return "SafetyNetResponse {" +"\n"+
                "nonce = '" + nonce.substring(0, 32) + "..." + '\'' + ",\n"+
                "timestampMs = " + timestampMs +",\n"+
                "apkPackageName = '" + apkPackageName + '\'' +",\n"+
                "apkDigestSha256 = '" + apkDigestSha256 + '\'' +",\n"+
                "ctsProfileMatch = " + ctsProfileMatch +",\n"+
                "apkCertificateDigestSha256 = '" + Arrays.toString(apkCertificateDigestSha256) + '\'' +",\n"+
                "extension = '" + extension + '\'' +",\n"+
                "basicIntegrity = " + basicIntegrity + "\n" +
                '}';
    }
}