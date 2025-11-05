package com.clear.balance.clearBalance.query;

public class UserQuery {

	public static final String COUNT_USER_EMAIL_QUERY = """
			SELECT COUNT(*) FROM users WHERE email = :email
			""";
	public static final String INSERT_USER_QUERY = null;
	public static final String INSERT_ACCOUNT_VERIFICATION_URL_QUERY = null;
}
