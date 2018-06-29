package it.oraclize.androidproof.datahandling;

import android.content.Context;
import android.util.Log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import it.oraclize.androidproof.data.AttestationObject;

public class AndroidProofWriter extends FileWriterHelper {

    private static final String TAG = "AndroidProofWriter";

    public AndroidProofWriter(Context context) {
        super(context);
    }

    /**
     * The method writes in storage the full attestationResult for our request.
     *
     * @param jwsResult the raw JSON Web Signature send by Google Safety Net Service
     **/
    public void writeToProofFile(String jwsResult, byte[] mResponse, byte[] mSignature, byte[] mRequestID, long startTime) {
        Log.d(TAG, "Writing proof to file...");
        String writeToProof = "writeToProofFile";

        try (FileOutputStream outputStream = new FileOutputStream(resultfile)) {
            CBORFactory f = new CBORFactory();
            ObjectMapper mapper = new ObjectMapper(f);
            // and then read/write data as usual

            AttestationObject obj =
                    new AttestationObject(mResponse, mRequestID, jwsResult, mSignature);
            byte[] cborData = mapper.writeValueAsBytes(obj);

            String proofPrefixString = "AP";
            byte androidProofVersion = 2;
            outputStream.write(proofPrefixString.getBytes(Charset.forName("UTF8")));
            outputStream.write(androidProofVersion);
            outputStream.write(cborData);

            Log.d(TAG, "AndroidProof Complete");
            appendToLogFile(STATUS, writeToProof, "status_message", "AndroidProof_Completed");

            long stopTime = System.currentTimeMillis();
            long elapsedTime = stopTime - startTime;

            Log.d("STATUS", Long.toString(elapsedTime));
        } catch (IOException e) {
            Log.e(TAG, "writeToProofFile Failed", e);
            appendToLogFile(ERROR, writeToProof, "error_message", e.getMessage());
        }
    }
}
