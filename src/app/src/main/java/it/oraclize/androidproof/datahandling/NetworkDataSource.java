package it.oraclize.androidproof.datahandling;

import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import static it.oraclize.androidproof.datahandling.FileWriterHelper.ERROR;
import static it.oraclize.androidproof.datahandling.FileWriterHelper.STATUS;

public class NetworkDataSource {

    private static final String TAG = "NetworkDataSource";

    private String url;
    private String method;
    private String dataPayload;
    private String setRequestProperty;
    private Integer readTimeOut;
    private Integer connectTimeOut;

    private String mResponseBody;
    private byte[] mResponse;

    FileWriterHelper filewriter;

    public NetworkDataSource (String url, String method, String dataPayload, String setRequestProperty, Integer readTimeOut, Integer connectTimeout, FileWriterHelper filewriter) {
        this.url = url;
        this.method = method;
        this.dataPayload = dataPayload;
        this.setRequestProperty = setRequestProperty;
        this.readTimeOut = readTimeOut;
        this.connectTimeOut = connectTimeout;
        this.filewriter = filewriter;
    }

    public byte[] fetchPage() throws Exception {
        URL obj;
        InputStream inStream;
        HttpsURLConnection conn = null;

        try {
            obj = new URL(url);
            conn = (HttpsURLConnection) obj.openConnection();

            conn.setReadTimeout(readTimeOut);
            conn.setConnectTimeout(connectTimeOut);
            conn.setDoInput(true);

            if (method == null) {
                conn.setRequestMethod("GET");
            } else {
                conn.setRequestMethod(method);
                if (dataPayload != null) {
                    conn.setRequestProperty("Content-Type", setRequestProperty);
                    conn.setDoInput(true);
                    DataOutputStream dStream = new DataOutputStream(conn.getOutputStream());
                    dStream.writeBytes(dataPayload);
                    dStream.flush();
                    dStream.close();
                }
            }

            conn.connect();
            inStream = new BufferedInputStream(conn.getInputStream());

            ByteArrayOutputStream byteArrayOut = new ByteArrayOutputStream();

            int c;
            byte[] buffer = new byte[4096];

            while ((c = inStream.read(buffer)) != -1) {
                byteArrayOut.write(buffer, 0, c);
            }

            byte[] responseBodyBytes = byteArrayOut.toByteArray();
            mResponseBody = new String(responseBodyBytes, "UTF8");
            Map<String, List<String>> headerMap = conn.getHeaderFields();
            filewriter.appendToLogFile(STATUS, "fetchPage", "page_headers", headerMap.toString());

            switch (conn.getResponseCode()) {
                case HttpsURLConnection.HTTP_OK:
                    Log.d(TAG, "Server Response is: \n" + mResponseBody);
                    filewriter.appendToLogFile(STATUS, "onHandleIntent", "successful_server_response", mResponseBody);
                    return responseBodyBytes;
                default:
                    filewriter.appendToLogFile(ERROR, "fetchPage", "error_message", conn.getResponseMessage());
                    return responseBodyBytes;
            }


        } catch (ClassCastException e) {
            Log.e(TAG, "Not HTTPS");
            filewriter.appendToLogFile(ERROR, "fetchPage", "error_message", "Not a HTTPS Url");
            throw new IOException("HTTPS_CONNECTION_ERROR: " + e.getMessage(), e);
        } catch (SocketTimeoutException e) {
            Log.e(TAG, "SocketTimeoutException error:" + e.getMessage());
            //TODO: Should use SafetyNet retry counter?
            //mResponse = fetchPage();
            filewriter.appendToLogFile(ERROR, "fetchPage", "error_message", "SocketTimeoutException Error");
            throw new SocketTimeoutException("SocketTimeoutException: " + e.getMessage());
        } catch (IOException e) {
            Log.e(TAG, "Connection Error");
            filewriter.appendToLogFile(ERROR, "fetchPage", "error_message", "Connection Error");
            throw new IOException("HTTPS_CONNECTION_ERROR: " + e.getMessage(), e);
        } catch (NullPointerException e) {
            Log.e(TAG, "Not enough time, response is null ");
            filewriter.appendToLogFile(ERROR, "fetchPage", "error_message", "Not enough time, response is null ");
            throw new IOException("CONNECTION_ERROR: Not enough time, response is null. " + e.getMessage(), e);
        } catch (Exception e) {
            Log.e(TAG, "Unknown error:" + e.getMessage());
            filewriter.appendToLogFile(ERROR, "fetchPage", "error_message", "Unknown error: " + e.getMessage());
            throw new IOException("Unknown error: " + e.getMessage(), e);
        } finally {
            try {
                conn.disconnect();
            } catch (Exception e) {
                Log.e(TAG, "Connection was never initialized");
            }
        }
    }
}
