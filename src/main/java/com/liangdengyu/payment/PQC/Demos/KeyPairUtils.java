package com.liangdengyu.payment.PQC.Demos;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;


public class KeyPairUtils {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 1024;
    private static final String PUBLIC_KEY_FILE = "publicKey.key";
    private static final String PRIVATE_KEY_FILE = "privateKey.key";
    private static final String KYBER_PUBLIC_KEY_FILE = "kyberpublickey.key";
    private static final String KYBER_PRIVATE_KEY_FILE = "kyberprivatekey.key";


    public static KeyPair getKeyPair() {
        try {
            // Check if the key pair already exists
            if (Files.exists(Paths.get(PUBLIC_KEY_FILE)) && Files.exists(Paths.get(PRIVATE_KEY_FILE))) {
                // Read the public key
                byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                // Read the private key
                byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

                // Return the existing key pair
                return new KeyPair(publicKey, privateKey);
            } else {
                // Generate a new key pair
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
                keyPairGenerator.initialize(KEY_SIZE);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                // Store the generated key pair
                storeKeyPair(keyPair);

                // Return the new key pair
                return keyPair;
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while generating or reading the key pair", e);
        }
    }
    
    public static KeyPair getKyberKeyPair() {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        try {
            if (Files.exists(Paths.get(KYBER_PUBLIC_KEY_FILE)) && Files.exists(Paths.get(KYBER_PRIVATE_KEY_FILE))) {
                // Read and return existing Kyber key pair
                byte[] publicKeyBytes = Files.readAllBytes(Paths.get(KYBER_PUBLIC_KEY_FILE));
                byte[] privateKeyBytes = Files.readAllBytes(Paths.get(KYBER_PRIVATE_KEY_FILE));
                PublicKey publicKey = getChrystalsKyberPublicKeyFromEncoded(publicKeyBytes);
                PrivateKey privateKey = getChrystalsKyberPrivateKeyFromEncoded(privateKeyBytes);
                return new KeyPair(publicKey, privateKey);
                

            } else {
                // Generate a new Kyber key pair
                KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
                System.out.println("test");
                KeyPair keyPair = generateChrystalsKyberKeyPair(KyberParameterSpec.kyber1024);
                System.out.println("test");

                // Store the generated Kyber key pair
                storeKyberKeyPair(keyPair);
                System.out.println("test");

                return keyPair;
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while generating or reading the Kyber key pair", e);
        }
    }

    public static KeyPair getKyberKeyPair(byte[] publicKeyBytes, byte[] privateKeyBytes) {
    	PublicKey publicKey = getChrystalsKyberPublicKeyFromEncoded(publicKeyBytes);
        PrivateKey privateKey = getChrystalsKyberPrivateKeyFromEncoded(privateKeyBytes);

        return new KeyPair(publicKey, privateKey);
    }
    public static PrivateKey getChrystalsKyberPrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("KYBER", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static KeyPair generateChrystalsKyberKeyPair(KyberParameterSpec kyberParameterSpec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC");
            kpg.initialize(kyberParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    static PublicKey getChrystalsKyberPublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("KYBER", "BCPQC");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

	public static KyberPublicKeyParameters generateKyberPublicKey(byte[] PublicKeyBytes) {
	    try {
	    	KyberParameters parameters = KyberParameters.kyber1024;
	    	return new KyberPublicKeyParameters(parameters, PublicKeyBytes);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}
    private static void storeKyberKeyPair(KeyPair keyPair) throws IOException {
        // Convert and store the Kyber public key
        // Note: Use appropriate encoding for Kyber keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] privateKeyByte = privateKey.getEncoded();
        byte[] publicKeyBytes = publicKey.getEncoded();
        Files.write(Paths.get(KYBER_PUBLIC_KEY_FILE), publicKeyBytes);
        Files.write(Paths.get(KYBER_PRIVATE_KEY_FILE), privateKeyByte);
    }



    private static void storeKeyPair(KeyPair keyPair) throws IOException {
        // Store the public key
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        Files.write(Paths.get(PUBLIC_KEY_FILE), x509EncodedKeySpec.getEncoded());

        // Store the private key
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        Files.write(Paths.get(PRIVATE_KEY_FILE), pkcs8EncodedKeySpec.getEncoded());
    }
}


