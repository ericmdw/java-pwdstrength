package com.devewm.passwordstrength;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;

import com.devewm.passwordstrength.exception.MaximumPasswordLengthExceededException;
import com.devewm.passwordstrength.exception.UnsupportedImplementationException;

/**
 * @author eric
 *
 */
public class PasswordStrengthMeter {
	public static final int PASSWORD_LENGTH_LIMIT = 256;
	
	private static Map<Class<? extends PasswordStrengthMeter>, Object> impls;
	
	protected PasswordStrengthMeter() {
	}
	
	public static PasswordStrengthMeter getInstance() {
		if(null == impls) {
			impls = new HashMap<Class<? extends PasswordStrengthMeter>, Object>();
		}
		Object impl = impls.get(PasswordStrengthMeter.class);
		if(null == impl) {
			impl = new PasswordStrengthMeter();
			impls.put(PasswordStrengthMeter.class, impl);
		}
		
		return (PasswordStrengthMeter) impl;
	}
	
	public static PasswordStrengthMeter getInstance(Class<? extends PasswordStrengthMeter> clazz) {
		if(null == impls) {
			impls = new HashMap<Class<? extends PasswordStrengthMeter>, Object>();
		}
		Object impl = impls.get(clazz);
		if(null == impl) {
			try {
				impl = clazz.newInstance();
			} catch (Exception e) {
				throw new UnsupportedImplementationException(clazz, e);
			}
			impls.put(clazz, impl);
		}
		
		return (PasswordStrengthMeter) impl;
	}
	
	public BigInteger check(String passwordPlaintext) {
		return check(passwordPlaintext, false);
	}
	
	public BigInteger check(String passwordPlaintext, boolean bypassLengthLimitCheck) {
		if(null == passwordPlaintext || passwordPlaintext.length() < 1) {
			return new BigInteger("0");
		}
		
		if(!bypassLengthLimitCheck && Character.codePointCount(passwordPlaintext, 0, passwordPlaintext.length()) > PASSWORD_LENGTH_LIMIT) {
			throw new MaximumPasswordLengthExceededException();
		}
		
		PasswordCharacterRange range = new PasswordCharacterRange(passwordPlaintext);
		BigInteger rangeSize = new BigInteger(Long.toString(range.size()));
		
		// determine number of iterations required for brute force attack
		// within this character range
		BigInteger result = new BigInteger("0");
		
		for(int i = 1; i < passwordPlaintext.length(); i++) {
			BigInteger iteration = rangeSize.pow(i);
			result = result.add(iteration);
		}
		
		for(int i = 1; i <= passwordPlaintext.length(); i++) {
			int power = passwordPlaintext.length() - i;
			long placeValue = range.position(passwordPlaintext.codePointAt(i - 1));
			
			if(power == 0 && placeValue == 0) {
				continue;
			}
			
			BigInteger multiplier = rangeSize.pow(power);
			BigInteger iteration = new BigInteger(Long.toString(placeValue)).multiply(multiplier);
			result = result.add(iteration);
		}
		
		return result.add(new BigInteger("1"));
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
		
		PasswordStrengthMeter passwordStrengthMeter = PasswordStrengthMeter.getInstance();
		
		DecimalFormat number = new DecimalFormat();
		number.setGroupingUsed(true);
		BigInteger result = passwordStrengthMeter.check(password.toString(), true);
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
