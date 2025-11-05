package com.clear.balance.clearBalance.exeception;

public class ApiException extends RuntimeException {

	private static final long serialVersionUID = -9217123965105195927L;

	public ApiException(String message) {
		super(message);
	}
}
