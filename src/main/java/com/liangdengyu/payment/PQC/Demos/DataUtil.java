package com.liangdengyu.payment.PQC.Demos;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;

public class DataUtil {
    public static SecretKey decryptrsakey(String encryptedKey,PrivateKey key) throws GeneralSecurityException {
    	ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    	long id = Thread.currentThread().getId();
    	long cpuTimeBefore = System.nanoTime();
        byte[] aesKeyBytes = Base64.getDecoder().decode(encryptedKey.trim());
        SecretKey originalKey = (SecretKey) unwrapKey(aesKeyBytes, "AES", key);
    	long cpuTimeAfter = System.nanoTime();
    	long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
    	System.out.println("RSA CPU Cost: "+cpuCost);
        return originalKey;
    }
	public static SecretKey decryptSecretKeyKyber(String encryptedSessionKey, PrivateKey key) {
    	long cpuTimeBefore = System.nanoTime();
        byte[] decryptedSessionKey = pqcGenerateChrystalsKyberDecryptionKey(key, Base64.getDecoder().decode(encryptedSessionKey));
        SecretKey decryptedAESKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
    	long cpuTimeAfter = System.nanoTime();
    	long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
    	System.out.println("Kyber CPU Cost: "+cpuCost);
        return decryptedAESKey;
    }
    public static byte[] aesdecrypted(String cipherText, SecretKey encryptedKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        cipher.init(Cipher.DECRYPT_MODE, encryptedKey, ivParameterSpec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return plainText;
    }

    public static byte[] aesdecrypted(byte[] encryptedData, SecretKey aesKey, PrivateKey key) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] decryptedBytes = aesCipher.doFinal(encryptedData);
        return decryptedBytes;
    }
    public static Key unwrapKey(byte[] wrappedKeyData, String wrappedKeyAlgorithm, PrivateKey unwrappingKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);
        return cipher.unwrap(wrappedKeyData, wrappedKeyAlgorithm, Cipher.SECRET_KEY);
    }

    public String encrypt(String input, String encryptedKey, String iv, PrivateKey key) throws Exception {
        byte[] aesKeyBytes = Base64.getDecoder().decode(encryptedKey.trim());
        SecretKey originalKey = (SecretKey) unwrapKey(aesKeyBytes, "AES", key);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        return encrypt(input,originalKey,ivParameterSpec);
    }
    // Encrypt a string with AES
    public static String encrypt(String input, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }
    public static SecretKey aesGenerateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey aesKey = keyGen.generateKey();
        return aesKey;
    }
    
    public static void AesEncryRSA(String input, KeyPair KeyPair) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        SecretKey aesKey = aesGenerateKey();//
        String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());
        System.out.println("Secret Key: " + encodedKey);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV();//
        byte[] encryptedData = aesCipher.doFinal(input.getBytes(StandardCharsets.UTF_8));//
        
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, KeyPair.getPublic());
        byte[] encryptedAesKey = rsaCipher.wrap(aesKey);

        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        String base64Iv = Base64.getEncoder().encodeToString(iv);
        String base64EncryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKey);
        
        try {

        	ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        	long id = Thread.currentThread().getId();
        	long cpuTimeBefore = bean.getThreadCpuTime(id);
        	SecretKey reversekey = decryptrsakey(base64EncryptedAesKey,KeyPair.getPrivate());
        	System.out.println(cpuTimeBefore);
        	long cpuTimeAfter = bean.getThreadCpuTime(id);
        	long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
        	System.out.println(cpuCost);
        	//SecretKey reversekey = decryptrsakey(base64EncryptedAesKey,KeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(base64Iv));
        	byte[] reverse = aesdecrypted(base64EncryptedData,reversekey,base64Iv);
        	String str = new String(reverse);
        	System.out.println(str);
        	String sentback = encrypt(str,reversekey,ivParameterSpec);
        	
        	byte[] sentbackbyte = aesdecrypted(sentback,aesKey,base64Iv);
        	String sentback2 = new String(sentbackbyte);
        	System.out.println(sentback2);
        	
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public static void AesEncryKyber(String data, KeyPair KeyPair) throws Exception {
        SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateChrystalsKyberEncryptionKey(KeyPair.getPublic());
        byte[] encryptedSessionKey = secretKeyWithEncapsulationSender.getEncapsulation();
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(secretKeyWithEncapsulationSender.getEncoded(), "AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());
        System.out.println("Secret Key: " + encodedKey);
        byte[] encryptedData = aesCipher.doFinal(data.getBytes());
        byte[] iv = aesCipher.getIV();//

        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        String base64Iv = Base64.getEncoder().encodeToString(iv);
        String base64encryptedSessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
        
        try {

        	ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        	long id = Thread.currentThread().getId();
        	long cpuTimeBefore = bean.getThreadCpuTime(id);
        	SecretKey reversekey = decryptSecretKeyKyber(base64encryptedSessionKey,KeyPair.getPrivate());
        	long cpuTimeAfter = bean.getThreadCpuTime(id);
        	long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
        	System.out.println(cpuCost);
        	//SecretKey reversekey = decryptSecretKeyKyber(base64encryptedSessionKey,KeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(base64Iv));
        	byte[] reverse = aesdecrypted(base64EncryptedData,reversekey,base64Iv);
        	String str = new String(reverse);
        	System.out.println(str);
        	String sentback = encrypt(str,reversekey,ivParameterSpec);
        	
        	byte[] sentbackbyte = aesdecrypted(sentback,aesKey,base64Iv);
        	String sentback2 = new String(sentbackbyte);
        	System.out.println(sentback2);
        	
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public static byte[] pqcGenerateChrystalsKyberDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
            keyGen.init(new KEMExtractSpec((PrivateKey) privateKey, encapsulatedKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc2.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static SecretKeyWithEncapsulation pqcGenerateChrystalsKyberEncryptionKey(PublicKey publicKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc1;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static void main(String[] args) throws Exception {

    	KeyPair keyPair = KeyPairUtils.getKeyPair();
    	KeyPair kyberkeyPair = KeyPairUtils.getKyberKeyPair();
    	ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    	long id = Thread.currentThread().getId();
    	long cpuTimeBefore = bean.getThreadCpuTime(id);
    	AesEncryRSA("doctor",keyPair);
    	long cpuTimeAfter = bean.getThreadCpuTime(id);
    	long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
    	System.out.println(cpuCost);
    	cpuTimeBefore = bean.getThreadCpuTime(id);
    	AesEncryKyber("doctor",kyberkeyPair);
    	cpuTimeAfter = bean.getThreadCpuTime(id);
    	cpuCost = cpuTimeAfter - cpuTimeBefore;
    	System.out.println(cpuCost);
    }
}
