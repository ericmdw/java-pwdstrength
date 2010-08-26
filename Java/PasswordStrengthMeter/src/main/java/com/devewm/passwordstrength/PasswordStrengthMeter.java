package com.devewm.passwordstrength;

import java.text.DecimalFormat;

/**
 * Algorithms:
 * every possible combination: 3^3 + 3^2 + 3^1
 * @author eric
 *
 */
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
		
		long rangeSize = highestCharCode - lowestCharCode + 1;
		for(int i = 1; i < passwordPlaintext.length(); i++) {
			result += Math.pow(rangeSize, i);
		}
		
		for(int i = 1; i <= passwordPlaintext.length(); i++) {
			int power = passwordPlaintext.length() - i;
			int placeValue = passwordPlaintext.charAt(i - 1) - lowestCharCode;
			
			if(power == 0 && placeValue == 0) {
				continue;
			}
			// 8 = 8 * 10^0, 80 = 8 * 10^1
			result += (placeValue * Math.pow(rangeSize, power)); 
		}
		
		return ++result;
	}
	
	public static void main(String[] args) {
		if(args.length < 1) {
			printUsage();
			return;
		}
		PasswordCharacterRange range = PasswordCharacterRange.MINIMAL_FOR_INPUT;
		int passwordStartIndex = 0;
		
		if(args[0].substring(0,1).equals("-")) {
			if(args.length < 2) {
				printUsage();
				return;
			}
			passwordStartIndex = 1;
			range = PasswordCharacterRange.valueOf(args[0].substring(1));
		}
		
		StringBuffer password = new StringBuffer();
		for(int i = passwordStartIndex; i < args.length; i++) {
			password.append(args[i] + " ");
		}
		password.setLength(password.length() - 1);
		
		DecimalFormat number = new DecimalFormat();
		number.setGroupingUsed(true);
		long result = PasswordStrengthMeter.check(password.toString(), range);
		System.out.println(password + ": " + number.format(result));
	}
	
	private static void printUsage() {
		String className = PasswordStrengthMeter.class.getName();
		System.out.println();
		System.out.println(className);
		System.out.println("http://devewm.com/projects/passwordstrength\n");
		System.out.println("Usage:");
		System.out.println("   java " + className + " [-<character range type>] <password>");
		System.out.println("example:\n   java " + className + " -ALPHABET_MIXED_CASE chickeN\n");
		System.out.println("Possible values for character range type:");
		for(PasswordCharacterRange range : PasswordCharacterRange.values()) {
			System.out.println("\t-" + range.name());
		}
		System.out.println();
	}
}
