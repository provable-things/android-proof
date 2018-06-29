package it.oraclize.androidproof;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.stream.Collectors;

public class Utils {


    private static final String TAG = "SafetyNetProof";

    public static String read(InputStream input) throws IOException {
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(input))) {
            return buffer.lines().collect(Collectors.joining("\n"));
        }
    }

    public static String[] calcApkCertificateDigests(final Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            Signature[] signatures = packageInfo.signatures;
            String[] certDigests = new String[signatures.length];

            for (int i = 0; i < signatures.length; i++) {
                byte[] cert = signatures[i].toByteArray();
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(cert, 0, cert.length);
                certDigests[i]=Base64.encodeToString(md.digest(), Base64.NO_WRAP);
            }

            return certDigests;

        } catch (Exception e) {
            Log.e(TAG, "Impossible to calculate apk certificate digest");
            e.printStackTrace();
        }
        return null;
    }


    public static String calcApkDigest(final Context context) {
        byte[] hashed = getApkFileDigest(context);
        return Base64.encodeToString(hashed, Base64.NO_WRAP);
    }

    private static byte[] getApkFileDigest(Context context) {
        String apkPath = context.getPackageCodePath();
        try {
            return getDigest(new FileInputStream(apkPath), "SHA-256");
        } catch (Throwable throwable) {
            Log.e(TAG, "Impossible to calculate apk digest");
            throwable.printStackTrace();
        }
        return null;
    }

    public static final int BUFFER_SIZE = 2048;

    public static byte[] getDigest(InputStream in, String algorithm) throws Throwable {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        try {
            DigestInputStream dis = new DigestInputStream(in, md);
            byte[] buffer = new byte[BUFFER_SIZE];
            while (dis.read(buffer) != -1) {
                //
            }
            dis.close();
        } finally {
            in.close();
        }
        return md.digest();
    }


}
