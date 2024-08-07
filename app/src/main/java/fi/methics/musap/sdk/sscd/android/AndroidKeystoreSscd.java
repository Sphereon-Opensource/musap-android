package fi.methics.musap.sdk.sscd.android;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import fi.methics.musap.sdk.internal.encryption.DecryptionReq;
import fi.methics.musap.sdk.internal.encryption.EncryptionReq;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.List;

import fi.methics.musap.sdk.api.MusapConstants;
import fi.methics.musap.sdk.attestation.AndroidKeyAttestation;
import fi.methics.musap.sdk.attestation.KeyAttestation;
import fi.methics.musap.sdk.extension.MusapSscdInterface;
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm;
import fi.methics.musap.sdk.internal.datatype.MusapKey;
import fi.methics.musap.sdk.internal.datatype.MusapLoA;
import fi.methics.musap.sdk.internal.datatype.MusapSignature;
import fi.methics.musap.sdk.internal.datatype.PublicKey;
import fi.methics.musap.sdk.internal.datatype.SignatureAlgorithm;
import fi.methics.musap.sdk.internal.datatype.SignatureFormat;
import fi.methics.musap.sdk.internal.datatype.SscdInfo;
import fi.methics.musap.sdk.internal.discovery.KeyBindReq;
import fi.methics.musap.sdk.internal.keygeneration.KeyGenReq;
import fi.methics.musap.sdk.internal.sign.SignatureReq;
import fi.methics.musap.sdk.internal.util.IdGenerator;
import fi.methics.musap.sdk.internal.util.MLog;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * MUSAP SSCD implementation for Android KeyStore
 * Note that this SSCD does not ask for authentication by default.
 * Authentication can be configured with step-up authentication policy.
 */
public class AndroidKeystoreSscd implements MusapSscdInterface<AndroidKeystoreSettings> {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 256;

    private Context context;

    private AndroidKeystoreSettings settings = new AndroidKeystoreSettings();

    public AndroidKeystoreSscd(Context context) {
        this.context = context;
    }

    public static final String SSCD_TYPE = "aks";

    @Override
    public MusapKey bindKey(KeyBindReq req) {
        // "Old" keys cannot be bound to MUSAP.
        // Use generateKey instead.
        throw new UnsupportedOperationException();
    }
    
    @Override
    public MusapKey generateKey(KeyGenReq req) throws Exception {

        Security.removeProvider("BC");
        MLog.d("Remove provider");
        SscdInfo sscd = this.getSscdInfo();
        String algorithm = this.resolveAlgorithm(req);
        AlgorithmParameterSpec algSspec = this.resolveAlgorithmParameterSpec(req);

        MLog.d("Generating with algorithm " + algorithm);

        int purposes = 0;
        if (req.getKeyUsage().contains("ENCRYPT") || req.getKeyUsage().contains("encrypt")) {
            purposes |= KeyProperties.PURPOSE_ENCRYPT;
        }
        if (req.getKeyUsage().contains("DECRYPT") || req.getKeyUsage().contains("decrypt")) {
            purposes |= KeyProperties.PURPOSE_DECRYPT;
        }
        if (req.getKeyUsage().contains("SIGN") || req.getKeyUsage().contains("sign")) {
            purposes |= KeyProperties.PURPOSE_SIGN;
        }
        if (req.getKeyUsage().contains("VERIFY") || req.getKeyUsage().contains("verify")) {
            purposes |= KeyProperties.PURPOSE_VERIFY;
        }
        if (purposes == 0) {
            purposes = KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY;
        }

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(req.getKeyAlias(), purposes);

        // If the key is for signing, configure the signature settings
        if ((purposes & KeyProperties.PURPOSE_SIGN) != 0 || (purposes & KeyProperties.PURPOSE_VERIFY) != 0) {
            builder.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setSignaturePaddings(
                            KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                            KeyProperties.SIGNATURE_PADDING_RSA_PSS);
        }

        // If the key is for encryption, configure the encryption settings
        if ((purposes & KeyProperties.PURPOSE_ENCRYPT) != 0 || (purposes & KeyProperties.PURPOSE_DECRYPT) != 0) {
            builder.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256);  // Example for AES
        }

        if (algSspec != null) {
            builder.setAlgorithmParameterSpec(algSspec);
            MLog.d("Algorithm spec " + algSspec);
        } else {
            MLog.d("No algorithm spec given");
        }

        if(req.isUserAuthenticationRequired()) {
            builder.setUserAuthenticationRequired(true);
            builder.setUserAuthenticationValidityDurationSeconds(90); // TODO configurable? (not available on iOS)
        }

        KeyGenParameterSpec spec = builder.build();
        MLog.d("Algorithm spec " + spec);
        
        // Handle symmetric and asymmetric key generation based on the algorithm
        if (KeyProperties.KEY_ALGORITHM_AES.equalsIgnoreCase(algorithm)) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, ANDROID_KEYSTORE);
            keyGenerator.init(spec);
            keyGenerator.generateKey();

            final MusapKey generatedKey = new MusapKey.Builder()
                    .setSscdType(MusapConstants.ANDROID_KS_TYPE)
                    .setKeyAlias(req.getKeyAlias())
                    .setSscdId(sscd.getSscdId())
                    .setLoa(Arrays.asList(MusapLoA.EIDAS_SUBSTANTIAL, MusapLoA.ISO_LOA3))
                    .setKeyId(IdGenerator.generateKeyId())
                    .setAlgorithm(req.getAlgorithm())
                    .setKeyUsages(List.of(req.getKeyUsage().split("[,;]")))
                    .build();
            MLog.d("Generated symmetric key with KeyURI " + generatedKey.getKeyUri());

            return generatedKey;
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, ANDROID_KEYSTORE);
            kpg.initialize(spec);
            KeyPair keyPair = kpg.generateKeyPair();
            MLog.d("Key generation successful");

            MusapKey generatedKey = new MusapKey.Builder()
                    .setSscdType(MusapConstants.ANDROID_KS_TYPE)
                    .setKeyAlias(req.getKeyAlias())
                    .setSscdId(sscd.getSscdId())
                    .setLoa(Arrays.asList(MusapLoA.EIDAS_SUBSTANTIAL, MusapLoA.ISO_LOA3))
                    .setPublicKey(new PublicKey(keyPair))
                    .setKeyId(IdGenerator.generateKeyId())
                    .setAlgorithm(req.getAlgorithm())
                    .build();
            MLog.d("Generated key with KeyURI " + generatedKey.getKeyUri());

            return generatedKey;
        }
    }


    @Override
    public MusapSignature sign(SignatureReq req) throws GeneralSecurityException, IOException {
        String alias = req.getKey().getKeyAlias();
        Security.removeProvider("BC");
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);

        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            MLog.d("Not an instance of a PrivateKeyEntry");
            return null;
        }

        SignatureAlgorithm algorithm = req.getAlgorithm();
        MLog.d("Signing " + new String(req.getData()) + " with algorithm " + algorithm);
        Signature s = Signature.getInstance(algorithm.getJavaAlgorithm());

        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();

        s.initSign(privateKey);
        s.update(req.getData());

        byte[] signature = s.sign();
        MLog.d("Signature byte len=" + signature.length);
        MLog.d("Signature hex=" + bytesToHex(signature));
        MLog.d("Signature=" + Base64.encodeToString(signature, Base64.DEFAULT));

        return new MusapSignature(signature, req.getKey(), algorithm, req.getFormat());
    }

    @Override
    public SscdInfo getSscdInfo() {
        return new SscdInfo.Builder()
                .setSscdName("Android KeyStore")
                .setSscdType(SSCD_TYPE)
                .setCountry("FI")
                .setProvider("Google")
                .setKeygenSupported(true)
                .setSupportedAlgorithms(Arrays.asList(
                        KeyAlgorithm.RSA_2K,
                        KeyAlgorithm.ECC_P256_R1,
                        KeyAlgorithm.ECC_P256_K1,
                        KeyAlgorithm.ECC_P384_K1))
                .setSupportedFormats(Arrays.asList(SignatureFormat.RAW))
                .build();
    }

    @Override
    public AndroidKeystoreSettings getSettings() {
        return settings;
    }

    @Override
    public KeyAttestation getKeyAttestation() {
        return new AndroidKeyAttestation();
    }

    @Override
    public byte[] encryptData(EncryptionReq encryptionReq) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        final SecretKey secretKey = (SecretKey) keyStore.getKey(encryptionReq.getKey().getKeyAlias(), null);
        
        final Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        final byte[] iv = cipher.getIV();
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] dataToEncrypt;
        if (encryptionReq.getSalt() != null) {
            dataToEncrypt = concatenate(encryptionReq.getSalt(), encryptionReq.getData());
        } else {
            dataToEncrypt = encryptionReq.getData();
        }

        final byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        return concatenate(iv, encryptedData);
    }

    @Override
    public byte[] decryptData(DecryptionReq decryptionReq) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        SecretKey secretKey = (SecretKey) keyStore.getKey(decryptionReq.getKey().getKeyAlias(), null);

        final Cipher cipher = Cipher.getInstance(AES_ALGORITHM); // FIXME dedup with encryptData
        final byte[] iv = cipher.getIV();
        System.arraycopy(decryptionReq.getData(), 0, iv, 0, iv.length);

        final GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        final byte[] decryptedData = cipher.doFinal(decryptionReq.getData(), iv.length, decryptionReq.getData().length - iv.length);

        // Handle salt if necessary
        if (decryptionReq.getSalt() != null) {
            final int saltLength = decryptionReq.getSalt().length;
            return removeSalt(decryptedData, saltLength);
        } else {
            return decryptedData;
        }
    }

    private byte[] concatenate(byte[] salt, byte[] data) {
        byte[] result = new byte[salt.length + data.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(data, 0, result, salt.length, data.length);
        return result;
    }

    private byte[] removeSalt(byte[] data, int saltLength) {
        byte[] result = new byte[data.length - saltLength];
        System.arraycopy(data, saltLength, result, 0, result.length);
        return result;
    }

    /**
     * Resolve the {@link AlgorithmParameterSpec} to use with key generation
     * @param req Key generation request
     * @return AlgorithmParameterSpec
     */
    private AlgorithmParameterSpec resolveAlgorithmParameterSpec(KeyGenReq req) {
        KeyAlgorithm algorithm = req.getAlgorithm();
        if (algorithm == null) {
            MLog.d("Null algorithm");
            return null;
        }
        if (algorithm.isRsa()) {
            MLog.d("RSA algorithm");
            return new RSAKeyGenParameterSpec(algorithm.bits, RSAKeyGenParameterSpec.F4);
        }
        if (algorithm.isAes()) {
            MLog.d("AES algorithm");
            return null; // Is set during enc/decryption
        } else {
            MLog.d("ECC algorithm");
            return new ECGenParameterSpec(algorithm.curve);
        }
    }

    /**
     * Resolve the key algorithm (EC or RSA)
     * @param req Key generation request
     * @return "EC" or "RSA" (default EC)
     */
    private String resolveAlgorithm(KeyGenReq req) {

        KeyAlgorithm algorithm = req.getAlgorithm();
        if (algorithm == null) return KeyProperties.KEY_ALGORITHM_EC;
        if (algorithm.isRsa()) {
            return KeyProperties.KEY_ALGORITHM_RSA;
        } if (algorithm.isAes()) {
            return KeyProperties.KEY_ALGORITHM_AES;
        } else {
            return KeyProperties.KEY_ALGORITHM_EC;
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
