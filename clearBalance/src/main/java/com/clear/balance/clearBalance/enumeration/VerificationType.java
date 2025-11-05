package com.clear.balance.clearBalance.enumeration;

public enum VerificationType {
	ACCOUNT("ACCOUNT"),
	PASSWORD("PASSWORD");
	
	private final String type;
	
	VerificationType(String type) {
        this.type = type;
    }
	
	public String getType() {
        return type.toLowerCase();
	}
}
