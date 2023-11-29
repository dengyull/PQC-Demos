package com.liangdengyu.payment.PQC.Demos;

import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;

@RestController
@RequestMapping("/api/payment/")
public class PaymentController {
	@Autowired
	private CustomUserDetailsService userDetailsService;

	KeyPair keyPair;
	KeyPair kyberkeyPair;
	KeyPair falcon;
	KeyPair Dilithium;
	CertificateGenerator CertificateGenerator;
	X509Certificate caCertificate;
	@PostConstruct
    public void init() {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	keyPair = KeyPairUtils.getKeyPair();
    	kyberkeyPair = KeyPairUtils.getKyberKeyPair();
    	CertificateGenerator = new CertificateGenerator();
    	try {
        	falcon = SignatureUtil.FalconKeyPair();
        	Dilithium = SignatureUtil.DilithiumKeyPair();
    		String caCertificateFilePath = "caCertificate.cer";
			caCertificate = CertificateGenerator.getOrCreateCACertificate(caCertificateFilePath);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }


	@PostMapping("/registerReq")
    public ResponseEntity<?> registerReq() {
		User user = userDetailsService.createUserWithoutCredentials();
    	String sentback = user.toJsonString();
        return ResponseEntity.ok(sentback);
    }
	@PostMapping("/registerReq/rsa")
    public ResponseEntity<?> RsaregisterReq(@RequestBody EncryRequest registrationRequest) {
		try {
        	SecretKey reversekey = DataUtil.decryptrsakey(registrationRequest.encryptedKey,keyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(registrationRequest.iv));
			User user = userDetailsService.createUserWithoutCredentials();
        	String sentback = DataUtil.encrypt(user.toJsonString(),reversekey,ivParameterSpec);
			return ResponseEntity.ok(sentback);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
    }
	@PostMapping("/registerReq/kyber")
    public ResponseEntity<?> kyberregisterReq(@RequestBody EncryRequest registrationRequest) {
		try {
        	SecretKey reversekey = DataUtil.decryptSecretKeyKyber(registrationRequest.encryptedKey,kyberkeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(registrationRequest.iv));
			User user = userDetailsService.createUserWithoutCredentials();
        	String sentback = DataUtil.encrypt(user.toJsonString(),reversekey,ivParameterSpec);
			return ResponseEntity.ok(sentback);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
    }
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequest registrationRequest) {
		//long currentTimeMillis = System.currentTimeMillis();
		//String json = registrationRequest.timestamp;
		//long gettime = Long.parseLong(json);
        //long elapsedTime = gettime - currentTimeMillis;
        //System.out.println("Timestamp from different: " + elapsedTime);
    	//long cpuTimeBefore = System.nanoTime();
	    try {
	        User user = userDetailsService.UserUsername(registrationRequest.username);
	        if( registrationRequest.password.equals(user.getPassword()) ) {
	            // Login successful
		    	//long cpuTimeAfterw = System.nanoTime();
		    	//long cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
		    	//System.out.println("login CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)"+cpuCost);
	            return ResponseEntity.ok(user);
	        } else {
	            // Password mismatch
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
	    } catch (Exception e) {
	        // Username not found
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
	    }
	}
	@PostMapping("/login/rsa")
	public ResponseEntity<?> Rsalogin(@RequestBody EncryRequest registrationRequest) {
		//long currentTimeMillis = System.currentTimeMillis();
		//String json = registrationRequest.timestamp;
		//long gettime = Long.parseLong(json);
        //long elapsedTime = gettime - currentTimeMillis;
        //System.out.println("Timestamp from different: " + elapsedTime);
    	//long cpuTimeBefore = System.nanoTime();
	    try {
        	SecretKey reversekey = DataUtil.decryptrsakey(registrationRequest.encryptedKey,keyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(registrationRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(registrationRequest.encryptedData,reversekey,registrationRequest.iv);
    		ObjectMapper mapper = new ObjectMapper();
    		LoginRequest LoginRequest = mapper.readValue(reverse, LoginRequest.class);
	    	//long cpuTimeAfterw = System.nanoTime();
	    	//long cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
	    	//System.out.println("rsa decrypt data CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)"+cpuCost);
    		
	        User user = userDetailsService.UserUsername(LoginRequest.username);
	    	//cpuTimeAfterw = System.nanoTime();
	    	//cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
	    	//System.out.println("login CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
	        PublicKey Signer= userDetailsService.UserSecuGetPublicKey(user);
	    	//cpuTimeAfterw = System.nanoTime();
	    	//cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
	    	//System.out.println("login CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
	        if(SignatureUtil.RsaSignVertify(Signer,SignatureUtil.createDigest(reverse),registrationRequest.sign)) {
		        //System.out.println("RsaSignVertify success");
		    	//cpuTimeAfterw = System.nanoTime();
		    	//cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
		    	//System.out.println("rsa vertify CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
		        if( LoginRequest.password.equals(user.getPassword()) ) {
		            // Login successful
			        //System.out.println("LoginRequest: " + "ok");
			    	//cpuTimeAfterw = System.nanoTime();
			    	//cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
			    	//System.out.println("login CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
		        	String sentback = DataUtil.encrypt(user.toJsonString(),reversekey,ivParameterSpec);

			    	//cpuTimeAfterw = System.nanoTime();
			    	//cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
			    	//System.out.println("login CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
		            return ResponseEntity.ok(sentback);
		        } else {
		            // Password mismatch
			        System.out.println("LoginRequest: " + "Password mismatch");
		            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
		        }
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
	        
	    } catch (Exception e) {
	        // Username not found
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
	    }
	}
	@PostMapping("/login/kyber")
	public ResponseEntity<?> kyberlogin(@RequestBody EncryRequest registrationRequest) {
		//long currentTimeMillis = System.currentTimeMillis();
		//String json = registrationRequest.timestamp;
		//long gettime = Long.parseLong(json);
        //long elapsedTime = gettime - currentTimeMillis;
        //System.out.println("Timestamp from different: " + elapsedTime);
    	//long cpuTimeBefore = System.nanoTime();
	    try {
        	SecretKey reversekey = DataUtil.decryptSecretKeyKyber(registrationRequest.encryptedKey,kyberkeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(registrationRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(registrationRequest.encryptedData,reversekey,registrationRequest.iv);
    		ObjectMapper mapper = new ObjectMapper();
    		LoginRequest LoginRequest = mapper.readValue(reverse, LoginRequest.class);
	    	//long cpuTimeAfterw = System.nanoTime();
	    	//long cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
	    	//System.out.println("kyber decrypt data CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)"+cpuCost);
    		
	        User user = userDetailsService.UserUsername(LoginRequest.username);
	    	byte[] publicBytes = Base64.getDecoder().decode(registrationRequest.publicKey);
	        if(SignatureUtil.SignVertify(registrationRequest.signmethod,publicBytes,SignatureUtil.createDigest(reverse),registrationRequest.sign)) {
		        System.out.println(registrationRequest.signmethod+"SignVertify success");
		        if( LoginRequest.password.equals(user.getPassword()) ) {
		            // Login successful
			        //System.out.println("LoginRequest: " + "ok");
		        	String sentback = DataUtil.encrypt(user.toJsonString(),reversekey,ivParameterSpec);

		            return ResponseEntity.ok(sentback);
		        } else {
		            // Password mismatch
			        System.out.println("LoginRequest: " + "Password mismatch");
		            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
		        }
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
	    } catch (Exception e) {
	        // Username not found
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
	    }
	}
	
	@PostMapping("/userSave")
    public ResponseEntity<?> UserSave(@RequestBody SaveRequest SaveRequest) throws Exception {
		User usr = userDetailsService.UserUsername(SaveRequest.username);		
		if (usr != null && SaveRequest.password.equals(usr.getPassword())) {
	        BigDecimal amount = userDetailsService.saveAmount(userDetailsService.UserUsername(SaveRequest.username), new BigDecimal(SaveRequest.amount));
            return ResponseEntity.ok(amount);
		} else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
		}
    }
	@PostMapping("/userSave/rsa")
	public ResponseEntity<?> RsauserSave(@RequestBody EncryRequest EncryRequest) throws Exception {
	    try {
	    	//long cpuTimeBefore = System.nanoTime();
        	SecretKey reversekey = DataUtil.decryptrsakey(EncryRequest.encryptedKey,keyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(EncryRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(EncryRequest.encryptedData,reversekey,EncryRequest.iv);
			ObjectMapper mapper = new ObjectMapper();
			SaveRequest SaveRequest = mapper.readValue(reverse, SaveRequest.class);
			User user = userDetailsService.UserUsername(SaveRequest.username);		
	        PublicKey Signer= userDetailsService.UserSecuGetPublicKey(user);
	        if(SignatureUtil.RsaSignVertify(Signer,SignatureUtil.createDigest(reverse),EncryRequest.sign)) {
		        //System.out.println("RsaSignVertify success");
				if (user != null && SaveRequest.password.equals(user.getPassword())) {
			        BigDecimal amount = userDetailsService.saveAmount(userDetailsService.UserUsername(SaveRequest.username), new BigDecimal(SaveRequest.amount));
		        	String sentback = DataUtil.encrypt(amount.toString(),reversekey,ivParameterSpec);
			    	//long cpuTimeAfter = System.nanoTime();
			    	//long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
			    	//System.out.println("RsauserSave total CPU Cost: "+cpuCost);
					return ResponseEntity.ok(sentback);
				} else {
		        	String sentback = DataUtil.encrypt("Invalid credentials.",reversekey,ivParameterSpec);
		            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(sentback);
				}
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }

	    } catch (Exception e) {
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
	    }
	}
	@PostMapping("/userSave/kyber")
	public ResponseEntity<?> kyberuserSave(@RequestBody EncryRequest EncryRequest) throws Exception {
	    try {
	    	//long cpuTimeBefore = System.nanoTime();
        	SecretKey reversekey = DataUtil.decryptSecretKeyKyber(EncryRequest.encryptedKey,kyberkeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(EncryRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(EncryRequest.encryptedData,reversekey,EncryRequest.iv);
			ObjectMapper mapper = new ObjectMapper();
			SaveRequest SaveRequest = mapper.readValue(reverse, SaveRequest.class);

	    	byte[] publicBytes = Base64.getDecoder().decode(EncryRequest.publicKey);
	        if(SignatureUtil.SignVertify(EncryRequest.signmethod,publicBytes,SignatureUtil.createDigest(reverse),EncryRequest.sign)) {
		        System.out.println(EncryRequest.signmethod+"SignVertify success");
		        User usr = userDetailsService.UserUsername(SaveRequest.username);		
				if (usr != null && SaveRequest.password.equals(usr.getPassword())) {
			        BigDecimal amount = userDetailsService.saveAmount(userDetailsService.UserUsername(SaveRequest.username), new BigDecimal(SaveRequest.amount));
		        	String sentback = DataUtil.encrypt(amount.toString(),reversekey,ivParameterSpec);
			    	//long cpuTimeAfter = System.nanoTime();
			    	//long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
			    	//System.out.println("kyberuserSave total CPU Cost: " + (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
					return ResponseEntity.ok(sentback);
				} else {
		        	String sentback = DataUtil.encrypt("Invalid credentials.",reversekey,ivParameterSpec);
		            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(sentback);
				}
			
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
			
			
	    } catch (Exception e) {
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
	    }
	}
	
	@PostMapping("/createpayment")
	public ResponseEntity<?> createPayment(@RequestBody PaymentRequest paymentRequest) {
	    try {
	        PaymentInformation paymentInformation = userDetailsService.createPayment(paymentRequest);
	        return new ResponseEntity<>("Create pay "+paymentInformation.getPaymentAmount()+" from "+paymentInformation.getDisbursementAccount()+" to "+ paymentInformation.getMerchantAccount(), HttpStatus.CREATED);
	    } catch (Exception e) {
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
	    }
	}
	

	@PostMapping("/createpayment/rsa")
	public ResponseEntity<?> RsacreatePayment(@RequestBody EncryRequest EncryRequest) throws Exception {
	    try {
        	SecretKey reversekey = DataUtil.decryptrsakey(EncryRequest.encryptedKey,keyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(EncryRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(EncryRequest.encryptedData,reversekey,EncryRequest.iv);
        	
        	byte[] publicBytes = Base64.getDecoder().decode(EncryRequest.publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        PublicKey publicKey = keyFactory.generatePublic(keySpec);
	        if(SignatureUtil.RsaSignVertify(publicKey,SignatureUtil.createDigest(reverse),EncryRequest.sign)) {
				PaymentRequest confirmationRequest = new PaymentRequest();
				confirmationRequest.data = new String(reverse);
		        PaymentInformation paymentInformation = userDetailsService.createPayment(confirmationRequest);
	        	String sentback = DataUtil.encrypt(paymentInformation.toJsonString(),reversekey,ivParameterSpec);
				return ResponseEntity.ok(sentback);
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
	        
	    } catch (Exception e) {
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
	    }
	}

	@PostMapping("/createpayment/kyber")
    public ResponseEntity<?> kybercreatePayment(@RequestBody EncryRequest EncryRequest) {
		try {
        	SecretKey reversekey = DataUtil.decryptSecretKeyKyber(EncryRequest.encryptedKey,kyberkeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(EncryRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(EncryRequest.encryptedData,reversekey,EncryRequest.iv);
        	

        	byte[] publicBytes = Base64.getDecoder().decode(EncryRequest.publicKey);
	        if(SignatureUtil.SignVertify(EncryRequest.signmethod,publicBytes,SignatureUtil.createDigest(reverse),EncryRequest.sign)) {
				PaymentRequest confirmationRequest = new PaymentRequest();
				confirmationRequest.data = new String(reverse);
		        PaymentInformation paymentInformation = userDetailsService.createPayment(confirmationRequest);
	        	String sentback = DataUtil.encrypt(paymentInformation.toJsonString(),reversekey,ivParameterSpec);
				return ResponseEntity.ok(sentback);
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
    }
	
	

	@PostMapping("/confirmpayment")
	public ResponseEntity<?> confirmPayment(@RequestBody PaymentRequest confirmationRequest) {
	    try {
	        PaymentInformation paymentInformation = userDetailsService.confirmPayment(confirmationRequest);
	        return new ResponseEntity<>(paymentInformation, HttpStatus.OK);
	    } catch (Exception e) {
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
	    }
	}
	

	@PostMapping("/confirmpayment/rsa")
	public ResponseEntity<?> RsaconfirmPayment(@RequestBody EncryRequest EncryRequest) throws Exception {
	    try {
        	SecretKey reversekey = DataUtil.decryptrsakey(EncryRequest.encryptedKey,keyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(EncryRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(EncryRequest.encryptedData,reversekey,EncryRequest.iv);        	

        	byte[] publicBytes = Base64.getDecoder().decode(EncryRequest.publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        PublicKey publicKey = keyFactory.generatePublic(keySpec);
	        if(SignatureUtil.RsaSignVertify(publicKey,SignatureUtil.createDigest(reverse),EncryRequest.sign)) {
				PaymentRequest confirmationRequest = new PaymentRequest();
				confirmationRequest.data = new String(reverse);
		        PaymentInformation paymentInformation = userDetailsService.confirmPayment(confirmationRequest);
	        	String sentback = DataUtil.encrypt(paymentInformation.toJsonString(),reversekey,ivParameterSpec);
				return ResponseEntity.ok(sentback);
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
	    } catch (Exception e) {
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
	    }
	}

	@PostMapping("/confirmpayment/kyber")
    public ResponseEntity<?> kyberconfirmPayment(@RequestBody EncryRequest EncryRequest) {
		try {
        	SecretKey reversekey = DataUtil.decryptSecretKeyKyber(EncryRequest.encryptedKey,kyberkeyPair.getPrivate());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(EncryRequest.iv));
        	byte[] reverse = DataUtil.aesdecrypted(EncryRequest.encryptedData,reversekey,EncryRequest.iv);

        	byte[] publicBytes = Base64.getDecoder().decode(EncryRequest.publicKey);
	        if(SignatureUtil.SignVertify(EncryRequest.signmethod,publicBytes,SignatureUtil.createDigest(reverse),EncryRequest.sign)) {
				PaymentRequest confirmationRequest = new PaymentRequest();
				confirmationRequest.data = new String(reverse);
		        PaymentInformation paymentInformation = userDetailsService.confirmPayment(confirmationRequest);
	        	String sentback = DataUtil.encrypt(paymentInformation.toJsonString(),reversekey,ivParameterSpec);
	        	System.out.println("kyber success");
				return ResponseEntity.ok(sentback);
	        } else {
	            // Password mismatch
		        System.out.println("LoginRequest: " + "SignVertify mismatch");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
	        }
		} catch (Exception e) {
			// TODO Auto-generated catch block
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
    }
	
	
	
	@PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegistrationRequest registrationRequest) {
		if(userDetailsService.usernameExists(registrationRequest.username)) {
			return ResponseEntity.badRequest().body("user already exist");
		}
 		User user = userDetailsService.updateUser(registrationRequest);
        return ResponseEntity.ok("Registered successfully");
    }
	@PostMapping("/register/rsa")
    public ResponseEntity<?> Rsaregister(@RequestBody RegistrationRequest registrationRequest) {
        try {
    		if(userDetailsService.usernameExists(registrationRequest.username)) {
    			return ResponseEntity.badRequest().body("user already exist");
    		}
        	User user = userDetailsService.updateUser(registrationRequest);
        	byte[] publicBytes = Base64.getDecoder().decode(registrationRequest.rsapublicKey);
        	byte[] privateBytes = Base64.getDecoder().decode(registrationRequest.rsaprivateKey);
        	X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
	        KeyFactory keyFactoryDilithium = KeyFactory.getInstance("Dilithium", "BCPQC");
	        KeyFactory keyFactoryFALCON = KeyFactory.getInstance("FALCON-1024", "BCPQC");
            PublicKey publicKeyDilithium = keyFactoryDilithium.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(registrationRequest.DilithiumpublicKey)));
            PublicKey publicKeyFALCON = keyFactoryFALCON.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(registrationRequest.FalconpublicKey)));
            X509Certificate entityCertificateFALCON = com.liangdengyu.payment.PQC.Demos.CertificateGenerator.signEntityCertificateFalcon("CN=EntityName, OU=EntityOrgUnit, O=EntityOrg, L=EntityCity, ST=EntityState, C=EntityCountry", publicKeyFALCON, caCertificate, falcon.getPrivate(), 365);
            X509Certificate entityCertificateDilithium = com.liangdengyu.payment.PQC.Demos.CertificateGenerator.signEntityCertificateDILITHIUM("CN=EntityName, OU=EntityOrgUnit, O=EntityOrg, L=EntityCity, ST=EntityState, C=EntityCountry", publicKeyDilithium, caCertificate, Dilithium.getPrivate(), 365);
            PrivateKey privateKeyFALCON = keyFactoryFALCON.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(registrationRequest.FalconprivateKey)));
            PrivateKey privateKeyDilithium = keyFactoryDilithium.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(registrationRequest.DilithiumprivateKey)));

            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);
        	userDetailsService.UserSecuSave(user, publicKey, privateKey);
            X509Certificate entityCertificate = com.liangdengyu.payment.PQC.Demos.CertificateGenerator.signEntityCertificate("CN=EntityName, OU=EntityOrgUnit, O=EntityOrg, L=EntityCity, ST=EntityState, C=EntityCountry", publicKey, caCertificate, keyPair.getPrivate(), 365);
            userDetailsService.CertificateSave(user, entityCertificate, entityCertificateFALCON, entityCertificateDilithium);
            String ss = userDetailsService.convertToPEM(entityCertificate);
        	sentcert sentcert = new sentcert();
        	sentcert.rsa = userDetailsService.convertToPEM(entityCertificate);
        	sentcert.Falcon = userDetailsService.convertToPEM(entityCertificateFALCON);
        	sentcert.Dilithium = userDetailsService.convertToPEM(entityCertificateDilithium);
        	userDetailsService.getCertificate(user,"Falcon");

            return ResponseEntity.ok(sentcert);
        } catch (Exception e) {
        	System.out.println(e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

	@PostMapping("/getcer")
	public ResponseEntity<?> getCer(@RequestBody getcertrequest encryRequest){
        try {
        	Long id = Long.parseLong(encryRequest.id);
			return ResponseEntity.ok(userDetailsService.getCertificate(id,encryRequest.mode));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}

	@PostMapping("/getpublic")
	public ResponseEntity<?> getpublic(@RequestBody getcertrequest encryRequest){
		switch (encryRequest.mode) {
		case "RSA":
			return ResponseEntity.ok(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
		case "Dilithium":
			return ResponseEntity.ok(Base64.getEncoder().encodeToString(Dilithium.getPublic().getEncoded()));
		case "Falcon":
			return ResponseEntity.ok(Base64.getEncoder().encodeToString(falcon.getPublic().getEncoded()));
		default:
			return null;
		}
	}
	
	@PostMapping("/balance")
    public ResponseEntity<?> balance(@RequestBody LoginRequest loginRequest) {
		return ResponseEntity.ok(userDetailsService.UserUsername(loginRequest.username).getAmount());
    }
}

class sentcert {
	public String rsa;
	public String Falcon;
	public String Dilithium;
}

class getcertrequest {
	public String id;
	public String mode;
}

class RegistrationRequest {
    public String id;
    public String username;
    public String password;
    public String rsapublicKey;
    public String rsaprivateKey;
    public String FalconpublicKey;
    public String FalconprivateKey;
    public String DilithiumpublicKey;
    public String DilithiumprivateKey;
}

class EncryRequest {
	public String encryptedData;
	public String iv;
	public String encryptedKey;
	public String sign;
	public String publicKey;//sign
	public String privatekey;
	public String ivs;
	public String encryptedprotectKey;
	public String signmethod;
	public String timestamp;
}

class LoginRequest {
    public String username;
    public String password;
	public String timestamp;
}

class PaymentRequest {
	public String data;
}

class SaveRequest {
    public String id;
    public String username;
    public String password;
    public String amount;
}

