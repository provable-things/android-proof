package it.oraclize.androidproof.datahandling;

import android.content.Context;
import android.os.Environment;
import android.support.annotation.NonNull;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileWriterHelper {
    private static final String TAG = "FileWriterHelper";

    public static final String STATUS = "Status";
    public static final String ERROR = "Error";

    private File dir;
    File resultfile;

    public FileWriterHelper(Context context) {
        dir = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS);
    }

    private void writeFile(File file) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            Log.d(TAG, "Using file at Path: \n" + file.getAbsolutePath());
            resultfile = file;
        } catch (IOException ioe) {
            Log.e(TAG, "writeFile: " + ioe.getMessage());
            throw new IOException("writeFile: " + ioe.getMessage());
        }
    }

    private boolean isMediaMounted() {
        return Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState());
    }

    @NonNull
    public void createFile(String filename) {

        try {
            if (isMediaMounted()) {
                File resultFile = new File(dir, filename);
                if (resultFile.exists()) {
                    Log.e(TAG, "requestID already used: " + resultFile.getAbsolutePath());
                    throw new IOException("requestID already used: " + resultFile.getAbsolutePath());
                } else {
                    writeFile(resultFile);
                }
            } else {
                Log.e(TAG, "media not mounted");
                throw new IOException("media not mounted");
            }
        } catch (IOException ioe) {
            Log.e(TAG, "Unable to create File:" + ioe.getMessage());
        }
    }

    public void appendToLogFile(String type, String method, String dataType, String data) {

        try (FileOutputStream outputStream = new FileOutputStream(resultfile, true)) {
            JSONObject errorMsg = new JSONObject();
            errorMsg.put("type", type);
            errorMsg.put("method", method);
            errorMsg.put("timestamp", System.currentTimeMillis());
            errorMsg.put("data_type", dataType);
            errorMsg.put("data", data);
            String newLine = "\n";

            outputStream.write(errorMsg.toString().getBytes());
            outputStream.write(newLine.getBytes());

        } catch (Exception e) {
            Log.e(TAG, "appendLogFile Failed", e);
        }
    }
}
