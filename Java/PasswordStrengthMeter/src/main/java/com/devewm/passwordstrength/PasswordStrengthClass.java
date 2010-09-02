package com.devewm.passwordstrength;

import java.math.BigInteger;

public enum PasswordStrengthClass implements Comparable<PasswordStrengthClass> {
	LENGTH_8_LOWER_CASE(8, 97, 122, new char[]{}),
	LENGTH_8_MIXED_CASE(8, 65, 122, new char[] { 'a' }),
	LENGTH_8_MIXED_CASE_WITH_NUMBER(8, 48, 122, new char[] { 'a', 'A' }),
	LENGTH_8_MIXED_CASE_WITH_NUMBER_AND_SYMBOL(8, 32, 122, new char[] { 'a', 'A', '0' }),
	
	LENGTH_10_LOWER_CASE(10, 97, 122, new char[]{}),
	LENGTH_10_MIXED_CASE(10, 65, 122, new char[] { 'a' }),
	LENGTH_10_MIXED_CASE_WITH_NUMBER(10, 48, 122, new char[] { 'a', 'A' }),
	LENGTH_10_MIXED_CASE_WITH_NUMBER_AND_SYMBOL(10, 32, 122, new char[] { 'a', 'A', '0' }),
	
	LENGTH_12_LOWER_CASE(12, 97, 122, new char[]{}),
	LENGTH_12_MIXED_CASE(12, 65, 122, new char[] { 'a' }),
	LENGTH_12_MIXED_CASE_WITH_NUMBER(12, 48, 122, new char[] { 'a', 'A' }),
	LENGTH_12_MIXED_CASE_WITH_NUMBER_AND_SYMBOL(12, 32, 122, new char[] { 'a', 'A', '0' }),
	
	LENGTH_16_LOWER_CASE(16, 97, 122, new char[]{}),
	LENGTH_16_MIXED_CASE(16, 65, 122, new char[] { 'a' }),
	LENGTH_16_MIXED_CASE_WITH_NUMBER(16, 48, 122, new char[] { 'a', 'A' }),
	LENGTH_16_MIXED_CASE_WITH_NUMBER_AND_SYMBOL(16, 32, 122, new char[] { 'a', 'A', '0' });
	
	
	private BigInteger iterationCount;
	
	private PasswordStrengthClass(int length, int lowerBound, int upperBound, char[] required) {
		StringBuffer basePassword = new StringBuffer();
		
		for(char c : required) {
			basePassword.append(c);
		}
		
		for(int i = 0; i < length - required.length; i++) {
			basePassword.append((char) lowerBound);
		}
		
		PasswordStrengthMeter passwordStrengthMeter = PasswordStrengthMeter.getInstance();
		this.iterationCount = passwordStrengthMeter.check(basePassword.reverse().toString(), false);
	}
	
	public BigInteger getIterations() {
		return this.iterationCount;
	}
}