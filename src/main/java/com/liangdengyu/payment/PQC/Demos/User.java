package com.liangdengyu.payment.PQC.Demos;

import java.math.BigDecimal;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_user")
public class User {
	
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

    private String username;
    private String password;
    private BigDecimal amount;
    private boolean enabled;
    
    public User(String username, String password) {
    	this.username = username;
    	this.password = password;
    	this.amount = BigDecimal.ZERO;
    	this.enabled = true;
    }
    
    public String toJsonString() {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"id\":").append(id).append(",");
        json.append("\"username\":\"").append(username).append("\",");
        json.append("\"password\":\"").append(password).append("\",");
        json.append("\"amount\":").append(amount).append(",");
        json.append("\"enabled\":").append(enabled);
        json.append("}");
        return json.toString();
    }


    public static User fromJsonString(String jsonString) {
        User user = new User();

        // Remove curly braces and split the JSON string into key-value pairs
        String[] keyValuePairs = jsonString
                .replace("{", "")
                .replace("}", "")
                .split(",");

        for (String keyValuePair : keyValuePairs) {
            String[] keyValue = keyValuePair.split(":");
            if (keyValue.length == 2) {
                String key = keyValue[0].trim().replace("\"", "");
                String value = keyValue[1].trim().replace("\"", "");

                switch (key) {
                    case "id":
                        //user.setId(Long.parseLong(value));
                        break;
                    case "username":
                        user.setUsername(value);
                        break;
                    case "password":
                        user.setPassword(value);
                        break;
                    case "amount":
                        user.saveAmount(new BigDecimal(value));
                        break;
                    case "enabled":
                        user.setEnabled(Boolean.parseBoolean(value));
                        break;
                    // Handle other properties if needed
                }
            }
        }

        return user;
    }
    
    public User() {
    	this.username = "deafult";
    	this.password = "deafult";
    	this.amount = BigDecimal.ZERO;
    	this.enabled = true;
	}
    
    public Long getId() {
		return id;
    }
    
    public BigDecimal saveAmount(BigDecimal num) {
        amount = amount.add(num);
        return amount;
    }

    public BigDecimal withdrawAmount(BigDecimal num) {
        amount = amount.subtract(num);
        return amount;
    }


	public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

	public BigDecimal getAmount() {
		return amount;
	}
	
	public void SetAmount(BigDecimal amount) {
		this.amount = amount;
		
	}
}