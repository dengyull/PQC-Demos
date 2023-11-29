package com.liangdengyu.payment.PQC.Demos;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.liangdengyu.payment.PQC.Demos.PaymentInformation.State;





@Service
public class CustomUserDetailsService {
	@Autowired
    private UserRepository userRepository;
	@Autowired
    private PaymentInformationRepository PaymentInformationRepository;
	@Autowired
    private UserSecuRepository UserSecuRepository;
	@Autowired
	private CertificateRepository certificateRepository;
	
	public String UserSecuSave(User user, PublicKey PublicKey, PrivateKey PrivateKey) {
		UserSecu save = new UserSecu(user.getId(), user.getUsername(), PublicKey, PrivateKey);
		UserSecuRepository.save(save);
		return "ok";
	}
	
	public boolean usernameExists(String username) {
        return userRepository.findByUsername(username).isPresent();
    }

	public String CertificateSave(User user, X509Certificate rsacertificate, X509Certificate falconcertificate, X509Certificate Dilithiumcertificate) throws Exception {
		Certificate save = new Certificate(user.getId(),rsacertificate,falconcertificate,Dilithiumcertificate);
		certificateRepository.save(save);
		return "ok";
	}

	public String getCertificate(User user,String mode) throws Exception {
		return getCertificate(user.getId(),mode);
	}
	public String getCertificate(Long id,String mode) throws Exception {
		switch (mode) {
		case "RSA":
			return getRSACertificate(id);
		case "Dilithium":
			return getDilithiumCertificate(id);
		case "Falcon":
			return getFalconCertificate(id);
		default:
			return null;
		}
	}
	public String getRSACertificate(Long id) throws Exception {
		Optional<Certificate> CertificateS= certificateRepository.findByUid(id);
		Certificate Certificate = CertificateS.get();
		return Certificate.getRSACertificate();
	}
	public String getFalconCertificate(Long id) throws Exception {
		Certificate Certificate = certificateRepository.findByUid(id).get();
		return Certificate.getFalconCertificate();
	}
	public String getDilithiumCertificate(Long id) throws Exception {
		Certificate Certificate = certificateRepository.findByUid(id).get();
		return Certificate.getDilithiumCertificate();
	}

	public PublicKey UserSecuGetPublicKey(User user) {
		UserSecu UserSecu = UserSecuRepository.findByUsername(user.getUsername()).get();
		return UserSecu.getPublicKey();
	}
	public PrivateKey UserSecuGetPrivateKey(User user) {
		UserSecu UserSecu = UserSecuRepository.findByUsername(user.getUsername()).get();
		return UserSecu.getPrivateKey();
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
    
    public void register(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }
        System.out.println(user.getPassword());

        User newUser = new User();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(user.getPassword());
        newUser.setEnabled(true);

        userRepository.save(newUser);
    }
    
    public User UserUsername(String username)  {
        Optional<com.liangdengyu.payment.PQC.Demos.User> user = userRepository.findByUsername(username);
        return user.get();
    }
    
    public User createUserWithoutCredentials() {
        User user = new User();
        return userRepository.save(user);
    }
    
    public User updateUser(RegistrationRequest request) {
        User existingUser = userRepository.findById(Long.parseLong(request.id)).orElseThrow(() -> new RuntimeException("User not found"));
        System.out.println("updateUser");
        if(request.username != "deafult") {
            existingUser.setUsername(request.username);
        }
        if(request.password != "deafult") {
            existingUser.setPassword((request.password));
        }

        return userRepository.save(existingUser);
    }
    
    public BigDecimal saveAmount(User user, BigDecimal num) {
        user.saveAmount(num);
        userRepository.save(user);
        return user.getAmount();
    }

	public PaymentInformation confirmPayment(PaymentRequest confirmationRequest) throws JsonMappingException, JsonProcessingException {
		// TODO Auto-generated method stub
		ObjectMapper mapper = new ObjectMapper();
		PaymentInformation PaymentInformation = mapper.readValue(confirmationRequest.data, PaymentInformation.class);
		
		
		List<PaymentInformation> PaymentInformationOpt = PaymentInformationRepository.findBydisbursementAccount(PaymentInformation.getDisbursementAccount());
		for (int i = 0; i < PaymentInformationOpt.size(); i++) {
			PaymentInformation entity = PaymentInformationOpt.get(i);
	        System.out.println(entity.getState());
			if(entity.getMerchantAccount().equals(PaymentInformation.getMerchantAccount())&&entity.getAlternatePassword().equals(PaymentInformation.getAlternatePassword())&&entity.getPaymentAmount().equals(PaymentInformation.getPaymentAmount())&&entity.getState().equals(State.PENDING)) {
	            System.out.println("save PaymentInformation");
	    		payment(PaymentInformation.getDisbursementAccount(),PaymentInformation.getMerchantAccount(),PaymentInformation.getPaymentAmount(),PaymentInformation.getAlternatePassword());

	    		entity.setstate(State.COMPLETED);
	    		PaymentInformation PaymentInformations = PaymentInformationRepository.save(entity);
	    		return PaymentInformations;
			}

		}
        System.out.println("no found");
        return null;
	}


    public void payment(String payerid, String payeeid, String num, String Password) {
        Optional<User> payerOpt = userRepository.findById(Long.valueOf(payerid));
        Optional<User> payeeOpt = userRepository.findById(Long.valueOf(payeeid));

        if(!payerOpt.isPresent() || !payeeOpt.isPresent()) {
            throw new IllegalArgumentException("Payer or Payee not found");
        }

        User payer = payerOpt.get();
        User payee = payeeOpt.get();

        //if (passwordEncoder.matches(Password, payer.getPassword())) {
        if (payer.getPassword().equals(Password)) {

            payer.withdrawAmount(BigDecimal.valueOf(Long.valueOf(num)));
            payee.saveAmount(BigDecimal.valueOf(Long.valueOf(num)));

            userRepository.save(payee);
            System.out.println(payee.getAmount());
            userRepository.save(payer);
            System.out.println(payer.getAmount());
        } else {
            System.out.println("password is different");

            throw new IllegalArgumentException("Payer Password is not currect");
        }
    }

	public PaymentInformation createPayment(PaymentRequest paymentRequest) throws JsonMappingException, JsonProcessingException {
		// TODO Auto-generated method stub
		ObjectMapper mapper = new ObjectMapper();
		PaymentInformation PaymentInformation = mapper.readValue(paymentRequest.data, PaymentInformation.class);
		PaymentInformation.setstate(State.PENDING);
        PaymentInformation PaymentInformations = PaymentInformationRepository.save(PaymentInformation);
		return PaymentInformations;
	}
}
