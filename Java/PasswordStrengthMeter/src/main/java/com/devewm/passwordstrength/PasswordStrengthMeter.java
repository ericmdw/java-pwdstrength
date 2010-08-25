package com.devewm.passwordstrength;

public class PasswordStrengthMeter {
	public static final long check(String passwordPlaintext) {
		return PasswordStrengthMeter.check(passwordPlaintext, null);
	}
	
	public static final long check(String passwordPlaintext, PasswordCharacterRange range) {
		if(null == passwordPlaintext || passwordPlaintext.length() < 1) {
			return 0;
		}
		
		int lowestCharCode = Integer.MAX_VALUE, highestCharCode = Integer.MIN_VALUE;
		if(range != null && range != PasswordCharacterRange.MINIMAL_FOR_INPUT) {
			lowestCharCode = range.getLowerBound();
			highestCharCode = range.getUpperBound();
		} else {
			// pre-scan to find the range of characters used
			for(int i = 0; i < passwordPlaintext.length(); i++) {
				int character = passwordPlaintext.charAt(i);
				if(lowestCharCode > character) {
					lowestCharCode = character;
				}
				if(highestCharCode < character) {
					highestCharCode = character;
				}
			}
		}
		
		// determine number of iterations required for brute force attack
		// within this character range
		long result = 0;
		result += (long) Math.pow(highestCharCode - lowestCharCode, passwordPlaintext.length() - 1);
		
		int lastChar = passwordPlaintext.charAt(passwordPlaintext.length() - 1);
		result += Math.abs(lastChar - lowestCharCode);
		
		return result;
	}
}
