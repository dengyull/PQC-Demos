package com.liangdengyu.payment.PQC.Demos;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SignatureUtil {
	
	public static byte[] createDigest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-384");
        byte[] hash = digest.digest(data);
        return hash;
    }

	public static boolean SignVertify(String method, byte[] publicBytes, byte[] datas, String Sign) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {

    	ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    	long id = Thread.currentThread().getId();
    	long cpuTimeBefore = System.nanoTime();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        System.out.println(method);
		switch (method) {
		case "Dilithium":
	        KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
	        PublicKey publicKey = keyFactory.generatePublic(keySpec);
	    	long cpuTimeAfter = System.nanoTime();
	    	long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
	    	System.out.println("Dilithium CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)"+cpuCost);
	    	System.out.println("Dilithium size: "+Sign.length());
	    	System.out.println("Dilithium publicKey size: "+publicBytes.length);
	        return DILITHIUMSignVertify(publicKey,datas,Sign);
        case "Falcon":
	        KeyFactory keyFactorys = KeyFactory.getInstance("FALCON-1024", "BCPQC");
	        PublicKey publicKeys = keyFactorys.generatePublic(keySpec);
	    	long cpuTimeAfterw = System.nanoTime();
	    	long cpuCostw = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
	    	System.out.println("Falcon CPU Cost: "+ (cpuCostw/ 1_000_000) +"ms("+cpuCostw+"ns)"+cpuCostw);
	    	System.out.println("Falcon size: "+Sign.length());
	    	System.out.println("Falcon publicKey size: "+publicBytes.length);
	        return FalconSignVertify(publicKeys,datas,Sign);
        }
		return false;
	}
	
	public static KeyPair FalconKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("FALCON-1024", "BCPQC");
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }
    public static KeyPair DilithiumKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DILITHIUM5", "BCPQC");
        KeyPair keyPaird = keyGen.generateKeyPair();
        return keyPaird;
    }
    
	public static String RSAsignData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }	
    
	public static String RSAsignData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }	
	public static String FalconsignData(String data, PrivateKey privKey) throws Exception{
        return FalconsignData(data.getBytes(StandardCharsets.UTF_8),privKey);
    }
    public static String FalconsignData(byte[] data, PrivateKey privKey) throws Exception {
        Signature signature = Signature.getInstance("FALCON-1024", "BCPQC");
        signature.initSign(privKey);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }
    public static String DilithiumsignData(String data, PrivateKey privKey) throws Exception{
        return DilithiumsignData(data.getBytes(StandardCharsets.UTF_8),privKey);
    }
    public static String DilithiumsignData(byte[] data, PrivateKey privKey) throws Exception {
        Signature signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initSign(privKey);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }
    
    public static boolean RsaSignVertify(PublicKey publicKey, byte[] decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

    	ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    	long id = Thread.currentThread().getId();
    	long cpuTimeBefore = System.nanoTime();
    	Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(decryptedData); 
        byte[] decodedSignature = Base64.getDecoder().decode(digitalsign);
        boolean result = signature.verify(decodedSignature);
    	long cpuTimeAfterw = System.nanoTime();
    	long cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
    	System.out.println("Rsa CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)"+cpuCost);
    	System.out.println("Rsa sign size: "+digitalsign.length());
    	System.out.println("Rsa publicKey size: "+publicKey.getEncoded().length);
        return result;
    }
    public static boolean FalconSignVertify(PublicKey publicKey, byte[] decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        Signature signature = Signature.getInstance("FALCON-1024", "BC");
        signature.initVerify(publicKey);
        signature.update(decryptedData);
        byte[] decodedSignature = Base64.getDecoder().decode(digitalsign);
        return signature.verify(decodedSignature);
    }
    public static boolean FalconSignVertify(PublicKey publicKey, String decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        
        return FalconSignVertify(publicKey,Base64.getDecoder().decode(decryptedData), digitalsign);
    }

    public static boolean DILITHIUMSignVertify(PublicKey publicKey, byte[] decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance("Dilithium");
        signature.initVerify(publicKey);
        signature.update(decryptedData); 
        byte[] decodedSignature = Base64.getDecoder().decode(digitalsign);
        return signature.verify(decodedSignature);
    }
    public static boolean DILITHIUMSignVertify(PublicKey publicKey, String decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        
        return DILITHIUMSignVertify(publicKey,Base64.getDecoder().decode(decryptedData), digitalsign);
    }
}
