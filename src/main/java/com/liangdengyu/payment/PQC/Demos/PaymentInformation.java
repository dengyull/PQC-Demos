package com.liangdengyu.payment.PQC.Demos;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "payment_information")
public class PaymentInformation {
	@Id
    @GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	
	enum State {
		PENDING, CONFIRM, CANCELED, COMPLETED
	}
	
    @Column(nullable = false)
    private String disbursementAccount;  // E.g., Bank account number or similar ID
    private String alternatePassword;   // Can be hashed for security
    
    @Column(precision = 19, scale = 4)
    private String paymentAmount;       // Can be changed to BigDecimal for better precision if required
    @Column(nullable = false)
    private String merchantAccount;     // E.g., Merchant's account number or ID
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private State state;                // Enum to track payment state
    public String toJsonString() {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"disbursementAccount\":\"").append(disbursementAccount).append("\",");
        json.append("\"alternatePassword\":\"").append(alternatePassword).append("\",");
        json.append("\"paymentAmount\":\"").append(paymentAmount).append("\",");
        json.append("\"merchantAccount\":\"").append(merchantAccount).append("\"");
        json.append("}");
        return json.toString();
    }
    public PaymentInformation() {
    	
    }
    public PaymentInformation(String disbursementAccount, String alternatePassword, String paymentAmount, String merchantAccount) {
        this.disbursementAccount = disbursementAccount;
        this.alternatePassword = alternatePassword;
        this.paymentAmount = paymentAmount;
        this.merchantAccount = merchantAccount;
    }

    // Getters and Setters
    public String getDisbursementAccount() {
        return disbursementAccount;
    }

    public void setDisbursementAccount(String disbursementAccount) {
        this.disbursementAccount = disbursementAccount;
    }

    public String getAlternatePassword() {
        return alternatePassword;
    }

    public void setAlternatePassword(String alternatePassword) {
        this.alternatePassword = alternatePassword;
    }

    public String getPaymentAmount() {
        return paymentAmount;
    }

    public void setPaymentAmount(String paymentAmount) {
        this.paymentAmount = paymentAmount;
    }

    public String getMerchantAccount() {
        return merchantAccount;
    }

    public void setMerchantAccount(String merchantAccount) {
        this.merchantAccount = merchantAccount;
    }
    
    public State getState() {
    	return state;
    }
    
    public Long getID() {
    	return id;
    }
    
    public void setstate(State st) {
    	this.state = st;
    }
}
