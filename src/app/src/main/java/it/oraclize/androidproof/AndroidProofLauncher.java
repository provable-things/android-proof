package it.oraclize.androidproof;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.Environment;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;

import it.oraclize.androidproof.data.AttestationCertificate;

public class AndroidProofLauncher extends AppCompatActivity {
    private static final String TAG = "AndroidProofLauncher";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "oraclize";
    public static final String ACTION = "it.oraclize.intent.Proof";
    private Context mContext = this;


    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent workIntent) {
            Intent serviceIntent = new Intent(mContext, AndroidProofService.class);
            String mURL = workIntent.getStringExtra("url");
            String mMethod = workIntent.getStringExtra("method");
            String mDataPayload = workIntent.getStringExtra("data");
            String mRequestID = workIntent.getStringExtra("requestID");
            String mReadOutTimeOut = workIntent.getStringExtra("readTimeout");
            String mConnectTimeOut = workIntent.getStringExtra("connectTimeout");
            String mSetRequestProperty = workIntent.getStringExtra("requestProperty");
            String mTimeoutBetweenRetries = workIntent.getStringExtra("timeoutBetweenRetries");
            String mRetriesMax = workIntent.getStringExtra("retriesMax");
            String mSafetyNetTimeout = workIntent.getStringExtra("safetyNetTimeout");
            String mApiKey = workIntent.getStringExtra("apiKey");

            Integer intReadOutTimeOut;
            Integer intConnTimeOut;
            Integer intTimeoutBetweenRetries;
            Integer intRetriesMax;
            Integer intSafetyNetTimeout;

            try {
                intReadOutTimeOut = Integer.parseInt(mReadOutTimeOut);
            } catch (NumberFormatException e) {
                intReadOutTimeOut = 12000;
            }


            try {
                intConnTimeOut = Integer.parseInt(mConnectTimeOut);
            } catch (NumberFormatException e) {
                intConnTimeOut = 15000;
            }


            try {
                intTimeoutBetweenRetries = Integer.parseInt(mTimeoutBetweenRetries);
            } catch (NumberFormatException e) {
                intTimeoutBetweenRetries = 5000;
            }

            try {
                intRetriesMax = Integer.parseInt(mRetriesMax);
            } catch (NumberFormatException e) {
                intRetriesMax = 3;
            }

            try {
                intSafetyNetTimeout = Integer.parseInt(mSafetyNetTimeout);
            } catch (NumberFormatException e) {
                intSafetyNetTimeout = 10000;
            }

            serviceIntent.putExtra("url", mURL);
            serviceIntent.putExtra("requestID", mRequestID);
            serviceIntent.putExtra("method", mMethod);
            serviceIntent.putExtra("data", mDataPayload);
            serviceIntent.putExtra("readTimeout", intReadOutTimeOut);
            serviceIntent.putExtra("connectTimeout", intConnTimeOut);
            serviceIntent.putExtra("retriesMax", intRetriesMax);
            serviceIntent.putExtra("timeoutBetweenRetries", intTimeoutBetweenRetries);
            serviceIntent.putExtra("requestProperty", mSetRequestProperty);
            serviceIntent.putExtra("safetyNetTimeout", intSafetyNetTimeout);
            serviceIntent.putExtra("apiKey", mApiKey);
            startService(serviceIntent);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.d(TAG,"App started");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.launcher);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        initializeKeystore();
        saveToFile(getCertChain());
        IntentFilter filterProof = new IntentFilter(ACTION);
        registerReceiver(mReceiver, filterProof);
    }


    @Override
    protected void onDestroy() {
        unregisterReceiver(mReceiver);
        super.onDestroy();
    }

    private void initializeKeystore ()  {

        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEY_STORE);
            ks.load(null);
            if (!ks.containsAlias(KEY_ALIAS)) {
                String attestationChallenge = "Oraclize";
                byte[] challenge = attestationChallenge.getBytes("UTF8");
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);

                kpg.initialize(
                        new KeyGenParameterSpec.Builder(
                                KEY_ALIAS,
                                KeyProperties.PURPOSE_SIGN
                        )
                                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                .setAttestationChallenge(challenge)
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .build());

                kpg.generateKeyPair();
                Log.d(TAG, "New Key Pair Created with alias: " + KEY_ALIAS);
            }
            else {
                Log.d(TAG, "Key Pair with alias " + KEY_ALIAS + " already existing");
            }


        } catch (Exception e) {
            Log.d("ERROR",e.toString());
        }

    }

    private AttestationCertificate getCertChain() {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEY_STORE);
            ks.load(null);
            Certificate[] certificateChain = ks.getCertificateChain(KEY_ALIAS);

            byte[] leaf = certificateChain[0].getEncoded();
            byte[] intermediate = certificateChain[1].getEncoded();
            byte[] root = certificateChain[2].getEncoded();

            return new AttestationCertificate(leaf, intermediate, root);

        } catch (Exception e) {
            Log.d(TAG, "Error", e);
            return null;
        }
    }


    private void saveToFile(AttestationCertificate obj) {
        String state = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(state)) {
            try {
                CBORFactory f = new CBORFactory();
                ObjectMapper mapper = new ObjectMapper(f);
                // and then read/write data as usual

                byte[] cborData = mapper.writeValueAsBytes(obj);

                String filename =  "AndroidProof" + ".chain";
                File dir =  this.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS);
                File resultFile = new File(dir, filename);
                FileOutputStream outputStream;
                outputStream =  new FileOutputStream(resultFile, false);
                outputStream.write(cborData);
                outputStream.close();
                Log.d(TAG, "AndroidProof Chain File Path: \n" + resultFile.getAbsolutePath());

            }
            catch (Exception e) {
                Log.e(TAG, "saveToFile Failed", e);
            }

        }
    }
}


