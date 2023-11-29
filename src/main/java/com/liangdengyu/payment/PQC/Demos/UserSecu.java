package com.liangdengyu.payment.PQC.Demos;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_usersecu")
public class UserSecu {
	@Id
	private Long uid;

    private String username;
    @Lob
	private PublicKey PublicKey;
	@Lob
	private PrivateKey PrivateKey;
	
	private byte[] session;
	
	public UserSecu() {
        // JPA requires a no-arg constructor
    }
	
	public UserSecu(Long uid, String username, PublicKey PublicKey, PrivateKey PrivateKey) {
		this.uid = uid;
		this.username = username;
		this.PublicKey = PublicKey;
		this.PrivateKey = PrivateKey;
	}

	public PublicKey getPublicKey() {
		return this.PublicKey;
	}
	public PrivateKey getPrivateKey() {
		return this.PrivateKey;
	}
	public void setSession(byte[] session) {
		this.session = session;
	}
	public byte[] getSession() {
		return session;
	}
}
