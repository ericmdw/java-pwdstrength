package com.devewm.passwordstrength;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.TreeSet;

import com.devewm.passwordstrength.exception.MaximumPasswordLengthExceededException;

/**
 * @author eric
 *
 */
public class PasswordStrengthMeter {
	public static final int PASSWORD_LENGTH_LIMIT = 256;
	
	public static final BigInteger check(String passwordPlaintext) {
		return PasswordStrengthMeter.check(passwordPlaintext, false);
	}
	
	public static final BigInteger check(String passwordPlaintext, boolean bypassMemoryLimitCheck) {
		if(null == passwordPlaintext || passwordPlaintext.length() < 1) {
			return new BigInteger("0");
		}
		
		if(!bypassMemoryLimitCheck && passwordPlaintext.length() > PASSWORD_LENGTH_LIMIT) {
			throw new MaximumPasswordLengthExceededException();
		}
		
		TreeSet<PasswordCharacterRange> ranges = new TreeSet<PasswordCharacterRange>();
		for(int i = 0; i < passwordPlaintext.length(); i++) {
			char c = passwordPlaintext.charAt(i);
			for(PasswordCharacterRange range : PasswordCharacterRange.values()) {
				if(range.contains(c)) {
					ranges.add(range);
					break;
				}
			}
		}
		
		long rangeSize = 0;
		for(PasswordCharacterRange range : ranges) {
			rangeSize += range.size();
		}
		
		// determine number of iterations required for brute force attack
		// within this character range
		BigInteger result = new BigInteger("0");
		
		for(int i = 1; i < passwordPlaintext.length(); i++) {
			BigInteger iteration = new BigInteger(Long.toString(rangeSize)).pow(i);
			result = result.add(iteration);
		}
		
		for(int i = 1; i <= passwordPlaintext.length(); i++) {
			int power = passwordPlaintext.length() - i;
			long placeValue = getCharacterPositionInRangeSet(passwordPlaintext.charAt(i - 1), ranges);;
			
			if(power == 0 && placeValue == 0) {
				continue;
			}
			// 8 = 8 * 10^0, 80 = 8 * 10^1
			BigInteger multiplier = new BigInteger(Long.toString(rangeSize)).pow(power);
			BigInteger iteration = new BigInteger(Long.toString(placeValue)).multiply(multiplier);
			result = result.add(iteration);
		}
		
		return result.add(new BigInteger("1"));
	}
	
	private static long getCharacterPositionInRangeSet(char character, TreeSet<PasswordCharacterRange> ranges) {
		long position = 0;
		
		for(PasswordCharacterRange range : ranges) {
			long rangePosition = range.position(character);
			if(rangePosition < 0) {
				position += range.size();
			} else {
				return position + rangePosition;
			}
		}
		return -1;
	}
	
	public static void main(String[] args) {
		if(args.length < 1) {
			printUsage();
			return;
		}
		StringBuffer password = new StringBuffer();
		for(int i = 0; i < args.length; i++) {
			password.append(args[i] + " ");
		}
		password.setLength(password.length() - 1);
		
		DecimalFormat number = new DecimalFormat();
		number.setGroupingUsed(true);
		BigInteger result = PasswordStrengthMeter.check(password.toString(), true);
		System.out.println(password + ": " + number.format(result));
	}
	
	private static void printUsage() {
		String className = PasswordStrengthMeter.class.getName();
		System.out.println();
		System.out.println(className);
		System.out.println("http://devewm.com/projects/passwordstrength\n");
		System.out.println("Usage:");
		System.out.println("   java <password>");
		System.out.println("example:\n   java " + className + " chickeN\n");
		
		System.out.println();
	}
}
