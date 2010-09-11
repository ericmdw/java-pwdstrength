package com.devewm.pwdstrength;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;

import com.devewm.pwdstrength.exception.MaximumPasswordLengthExceededException;
import com.devewm.pwdstrength.exception.UnsupportedImplementationException;

/**
 * <p>The main class which does the work of calculating password strength.</p>
 * <p>Password strength is calculated by simulating a sequential brute-force attack on a given password. For example, to compute the strength of <em>abc</em>, it would first try every possible 1-letter password and then every possible 2-letter password. Once reaching three letter passwords, it would start by trying <em>aaa</em>, then <em>aab</em> and so on until reaching <em>aaz</em>. At this point the next letter to the left increments to the next value and the final letter starts back at the beginning; the next password checked is <em>aba</em>. This process continues until the password is found.</p>
 * <p>The range of characters checked is determined by scanning the password's characters to see what unicode character blocks they fall in. All the occuring blocks will then be scanned during the simulated brute-force attack. For instance, if a password contains a single character in the cyrillic unicode block, all characters in that block will be checked when running the attack iteration count. (The Basic_Latin block has been subdivided into lowercase letters, uppercase letters, numbers, symbols, and control characters.)</p>
 * <p>With this approach, the method for counting the sequential brute-force iterations can be expressed mathematically as:
 * given <em>R</em> is the number of characters which could occur in the password; <em>L</em> is the length of the password; <em>P[n]</em> is the 0-based index of the <em>n</em>th character of the password in the range of possible characters; then<br/>
 * iterations = <em>(R^1 + R^2 + ... + R^(L-1)) + { P[0](R^(L-0)) + P[1](R^(L-1)) + ... + P[L-1](R^(L-L)) }</em>
 * </p>
 * <p>This class cannot be instantiated; to use it, get an instance of the class by calling the static <code>getInstance()</code> method. Subclasses should override <code>getInstance()</code> to provide a singleton instance of the appropriate type. The <code>getInstance(Class type)</code> method is provided as a convenience to access singleton instances of subtypes when applicable.</p>
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
	
	public boolean satisfiesStrengthClass(String password, PasswordStrengthClass strengthClass) {
		BigInteger iterationCount = null;
		try {
			iterationCount = iterationCount(password);
		} catch(MaximumPasswordLengthExceededException lengthException) {
			// length alone will make this password satisfy any
			// standard PasswordStrengthClass
			return true;
		}
		
		return iterationCount.compareTo(strengthClass.getIterations()) >= 0;
	}
	
	public BigInteger iterationCount(String passwordPlaintext) {
		return iterationCount(passwordPlaintext, false);
	}
	
	public BigInteger iterationCount(String passwordPlaintext, boolean bypassLengthLimitCheck) {
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
		BigInteger result = passwordStrengthMeter.iterationCount(password.toString(), true);
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
