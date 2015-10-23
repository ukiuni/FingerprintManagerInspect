package com.ukiuni.fingerinspect;

import android.app.Activity;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.KeyPairGenerator;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class FingerAuthActivity extends Activity {
    byte[] key = new byte[256];

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_finger_auth);
        final FingerprintManager fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        if (fingerprintManager.isHardwareDetected() || fingerprintManager.hasEnrolledFingerprints()) {//指紋を取るハードウェアがあり、かつ、指紋が登録されていることをチェック。
            Cipher cipher = null;
            try {
                String keyName = "myKey2";
                String keyStoreName = "AndroidKeyStore";
                KeyStore keyStore = KeyStore.getInstance(keyStoreName);
                keyStore.load(null);
                cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7);
                SecretKey key = (SecretKey) keyStore.getKey(keyName, null);
                if (null == key) {
                    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, keyStoreName);
                    keyGenerator.initialize(new KeyGenParameterSpec.Builder(keyName,
                            KeyProperties.PURPOSE_ENCRYPT |
                                    KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setUserAuthenticationRequired(true)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .build());
                    keyGenerator.generateKeyPair();
                    key = (SecretKey) keyStore.getKey(keyName, null);
                }

                cipher.init(Cipher.ENCRYPT_MODE, key);

            } catch (Exception ignored) {
            }
            final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
            final CancellationSignal signal = new CancellationSignal();
            signal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
                @Override
                public void onCancel() {
                    Log.v("", "cancelled");
                }
            });
            fingerprintManager.authenticate(cryptoObject, signal, 0, new FingerprintManager.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    Log.e("", "error " + errorCode + " " + errString);
                }

                @Override
                public void onAuthenticationFailed() {
                    Log.e("", "failed");
                }

                @Override
                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                    Cipher cipher = result.getCryptoObject().getCipher();
                    Log.i("", "auth success " + cipher);
                    try {
                        byte[] responseToServer = cipher.doFinal("server challenge".getBytes());
                    } catch (Exception ignored) {
                    }
                }
            }, new Handler());
        }
    }
}
