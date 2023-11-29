package com.liangdengyu.payment.PQC.Demos;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.bouncycastle.util.encoders.Base64;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_cer")
public class Certificate {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	

	private Long uid;

	@Lob
    private String Rsacertificate;
	@Lob
    private String falconcertificate;
	@Lob
    private String Dilithiumcertificate;

	public Certificate() {
    }
	
    public Certificate(Long uid, String certificate, String falconcertificate, String Dilithiumcertificate) {
    	this.uid = uid;
    	this.Rsacertificate = certificate;
    	this.falconcertificate = falconcertificate;
    	this.Dilithiumcertificate = Dilithiumcertificate;
    }
    public Certificate(Long uid, X509Certificate rsacertificate, X509Certificate falconcertificate, X509Certificate Dilithiumcertificate) throws Exception {
    	this.uid = uid;
    	this.Rsacertificate = convertToPEM(rsacertificate);
    	this.falconcertificate = convertToPEM(falconcertificate);
    	this.Dilithiumcertificate = convertToPEM(Dilithiumcertificate);;
    }
    
	public X509Certificate convertFromPEM(String pemString) throws Exception {
	    // Remove the first and last lines (PEM headers and footers)
	    String base64Encoded = pemString.replaceAll("-----BEGIN CERTIFICATE-----", "")
	                                    .replaceAll("-----END CERTIFICATE-----", "")
	                                    .replaceAll("\\s", ""); // Remove all whitespace
	
	    // Decode the Base64 encoded bytes
	    byte[] certificateBytes = Base64.decode(base64Encoded);
	
	    // Create a CertificateFactory
	    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
	
	    // Generate X509Certificate
	    X509Certificate certificate = (X509Certificate) certificateFactory
	                                  .generateCertificate(new ByteArrayInputStream(certificateBytes));
	
	    return certificate;
	}

    public String convertToPEM(X509Certificate certificate) throws Exception {
        // Convert the X509Certificate to PEM format
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        pem.append(Base64.toBase64String(certificate.getEncoded()).replaceAll("(.{64})", "$1\n"));
        pem.append("\n-----END CERTIFICATE-----\n");
        return pem.toString();
    }
    
    // Getter for uid
    public Long getUid() {
        return uid;
    }

    // Getter for certificate
    public String getRSACertificate() {
        return Rsacertificate;
    }

    // Getter for certificate
    public String getFalconCertificate() {
        return falconcertificate;
    }

    // Getter for certificate
    public String getDilithiumCertificate() {
        return Dilithiumcertificate;
    }
    
}

