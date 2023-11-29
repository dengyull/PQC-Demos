package com.liangdengyu.payment.PQC.Demos;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateGenerator {

	static {
        Security.addProvider(new BouncyCastleProvider());
    }
	
	public static X509Certificate generateSelfSignedCACertificate(String subjectDN, KeyPair caKeyPair, int validityDays) throws Exception {
	    Date notBefore = new Date();
	    Date notAfter = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));

	    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
	            new X500Name(subjectDN),
	            BigInteger.valueOf(System.currentTimeMillis()),
	            notBefore,
	            notAfter,
	            new X500Name(subjectDN),
	            caKeyPair.getPublic());

	    BasicConstraints basicConstraints = new BasicConstraints(true); // CA: true
	    certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

	    KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.cRLSign);
	    certBuilder.addExtension(Extension.keyUsage, true, usage.toASN1Primitive());

	    ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caKeyPair.getPrivate());
	    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
	}

	public static X509Certificate signEntityCertificate(
	        String entitySubjectDN,
	        PublicKey entityPublicKey,  
	        X509Certificate caCertificate,
	        PrivateKey caPrivateKey,
	        int validityDays) throws Exception {

	    Date notBefore = new Date();
	    Date notAfter = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));

	    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
	    		new X500Name(caCertificate.getSubjectX500Principal().getName()),
	            BigInteger.valueOf(System.currentTimeMillis()),
	            notBefore,
	            notAfter,
	            new X500Name(entitySubjectDN),
	            entityPublicKey);

	    BasicConstraints basicConstraints = new BasicConstraints(false); // Not a CA
	    certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

	    KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
	    certBuilder.addExtension(Extension.keyUsage, false, usage.toASN1Primitive());

	    ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caPrivateKey);
	    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
	}

	public static X509Certificate signEntityCertificateFalcon(
	        String entitySubjectDN,
	        PublicKey entityPublicKey,  
	        X509Certificate caCertificate,
	        PrivateKey caPrivateKey,
	        int validityDays) throws Exception {

	    Date notBefore = new Date();
	    Date notAfter = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));

	    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
	    		new X500Name(caCertificate.getSubjectX500Principal().getName()),
	            BigInteger.valueOf(System.currentTimeMillis()),
	            notBefore,
	            notAfter,
	            new X500Name(entitySubjectDN),
	            entityPublicKey);

	    BasicConstraints basicConstraints = new BasicConstraints(false); // Not a CA
	    certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

	    KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
	    certBuilder.addExtension(Extension.keyUsage, false, usage.toASN1Primitive());

	    ContentSigner signer = new JcaContentSignerBuilder("FALCON-1024").build(caPrivateKey);
	    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
	}

	public static X509Certificate signEntityCertificateDILITHIUM(
	        String entitySubjectDN,
	        PublicKey entityPublicKey,  
	        X509Certificate caCertificate,
	        PrivateKey caPrivateKey,
	        int validityDays) throws Exception {

	    Date notBefore = new Date();
	    Date notAfter = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));

	    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
	    		new X500Name(caCertificate.getSubjectX500Principal().getName()),
	            BigInteger.valueOf(System.currentTimeMillis()),
	            notBefore,
	            notAfter,
	            new X500Name(entitySubjectDN),
	            entityPublicKey);

	    BasicConstraints basicConstraints = new BasicConstraints(false); // Not a CA
	    certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

	    KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
	    certBuilder.addExtension(Extension.keyUsage, false, usage.toASN1Primitive());

	    ContentSigner signer = new JcaContentSignerBuilder("DILITHIUM").build(caPrivateKey);
	    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
	}


    public static X509Certificate generateSelfSignedCertificate(String subjectDN, int validityDays) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (validityDays * 24L * 60 * 60 * 1000));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(subjectDN),
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                new X500Name(subjectDN),
                keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true); // true if this cert is CA.
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        certBuilder.addExtension(Extension.keyUsage, false, usage.toASN1Primitive());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }


    public static X509Certificate getOrCreateCACertificate(String caCertificateFilePath) throws Exception {
        X509Certificate caCertificate;

        // Check if the CA certificate file exists
        File caCertificateFile = new File(caCertificateFilePath);
        if (caCertificateFile.exists()) {
            // If the file exists, load the CA certificate from the file
            FileInputStream caCertificateInputStream = new FileInputStream(caCertificateFile);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            caCertificate = (X509Certificate) certificateFactory.generateCertificate(caCertificateInputStream);
            caCertificateInputStream.close();
            System.out.println("Loaded CA Certificate from file:");
            System.out.println(caCertificate);
        } else {
            // If the file does not exist, generate a new CA certificate
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair caKeyPair = keyPairGenerator.generateKeyPair();

            caCertificate = generateSelfSignedCACertificate("CN=MyCA, OU=MyOrgUnit, O=MyOrg, L=MyCity, ST=MyState, C=MyCountry", caKeyPair, 3650); // valid for 10 years
            System.out.println("Generated and saved CA Certificate:");
            System.out.println(caCertificate);

            // Save the CA certificate to the file
            FileOutputStream caCertificateOutputStream = new FileOutputStream(caCertificateFile);
            caCertificateOutputStream.write(caCertificate.getEncoded());
            caCertificateOutputStream.close();
        }
        return caCertificate;
    }

    public static X509Certificate getOrCreateCACertificatekyber(String caCertificateFilePath) throws Exception {
        X509Certificate caCertificate;

        // Check if the CA certificate file exists
        File caCertificateFile = new File(caCertificateFilePath);
        if (caCertificateFile.exists()) {
            // If the file exists, load the CA certificate from the file
            FileInputStream caCertificateInputStream = new FileInputStream(caCertificateFile);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            caCertificate = (X509Certificate) certificateFactory.generateCertificate(caCertificateInputStream);
            caCertificateInputStream.close();
            System.out.println("Loaded CA Certificate from file:");
            System.out.println(caCertificate);
        } else {
            // If the file does not exist, generate a new CA certificate
        	KeyPair kyberkeyPair = KeyPairUtils.getKyberKeyPair();

            caCertificate = generateSelfSignedCACertificate("CN=MyCA, OU=MyOrgUnit, O=MyOrg, L=MyCity, ST=MyState, C=MyCountry", kyberkeyPair, 3650); // valid for 10 years
            System.out.println("Generated and saved CA Certificate:");
            System.out.println(caCertificate);

            // Save the CA certificate to the file
            FileOutputStream caCertificateOutputStream = new FileOutputStream(caCertificateFile);
            caCertificateOutputStream.write(caCertificate.getEncoded());
            caCertificateOutputStream.close();
        }

        return caCertificate;
    }
    

    public static boolean verifyCertificate(X509Certificate cert, PublicKey caPublicKey) {
        try {
            cert.checkValidity(); // Checks whether the certificate is currently valid
            cert.verify(caPublicKey); // Verifies the certificate's signature with the CA's public key
            System.out.println("Certificate is valid.");
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            System.out.println("Certificate is not valid: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("Error during certificate verification: " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) {
        try {
            // Generate CA KeyPair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair caKeyPair = KeyPairUtils.getKeyPair();

            // Specify the file path for storing and loading the CA certificate
            String caCertificateFilePath = "caCertificate.cer";

            // Get or create the CA certificate
            X509Certificate caCertificate = getOrCreateCACertificatekyber(caCertificateFilePath);
            System.out.println("CA Certificate:");
            System.out.println(caCertificate);

            // Generate an entity's KeyPair
            KeyPair entityKeyPair = keyPairGenerator.generateKeyPair();

            // Sign the entity's certificate using the CA's private key
            X509Certificate entityCertificate = signEntityCertificate("CN=EntityName, OU=EntityOrgUnit, O=EntityOrg, L=EntityCity, ST=EntityState, C=EntityCountry", entityKeyPair.getPublic(), caCertificate, caKeyPair.getPrivate(), 365);
            System.out.println("\nEntity Certificate:");
            System.out.println(entityCertificate);
            

            // Verify the entity's certificate
            System.out.println("\nVerifying Entity Certificate:");
            boolean isEntityCertValid = verifyCertificate(entityCertificate, caKeyPair.getPublic());
            System.out.println("Entity Certificate is valid: " + isEntityCertValid);

            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
