package com.devewm.pwdstrength;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
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
 * iterations = <em>(R^1 + R^2 + ... + R^(L-1)) + { P[0](R^(L-0)) + P[1](R^(L-1)) + ... + P[L-1](R^(L-L)) + 1}</em>
 * </p>
 * <p>This class cannot be instantiated; to use it, get an instance of the class by calling the static <code>getInstance()</code> method. Subclasses should override <code>getInstance()</code> to provide a singleton instance of the appropriate type. The <code>getInstance(Class type)</code> method is provided as a convenience to access singleton instances of subtypes when applicable.</p>
 *
 */
public class PasswordStrengthMeter {
	/**
	 * The maximum password length (in unicode codepoints) for which
	 * calculations will be run. To bypass this limit, use
	 * <code>iterationCount()</code> and pass <code>true</code> as the
	 * <code>bypassLengthLimitCheck</code> parameter.
	 */
	public static final int PASSWORD_LENGTH_LIMIT = 256;
	private static final int BIG_DECIMAL_SCALE = 4096;
	
	private boolean verifyPartialSumResult = false;
	
	/**
	 * Implementation instance cache to assist this and subclasses with
	 * singleton usage.
	 */
	private static Map<Class<? extends PasswordStrengthMeter>, Object> impls;
	
	/**
	 * Reducing constructor visibility to enforce singleton usage. To
	 * get an instance of this class, call <code>getInstance()</code>.
	 */
	protected PasswordStrengthMeter() {
	}
	
	/**
	 * Get an instance of <code>PasswordStrengthMeter</code>
	 * @return an instance of <code>PasswordStrengthMeter</code>
	 */
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
	
	/**
	 * Get the singleton instance of a <code>PasswordStrengthMeter</code>
	 * subclass. This is here as a convenience to custom factory-type
	 * classes so they don't have to manage the caching of the subclass
	 * implementations.
	 * @param clazz the <code>PasswordStrengthMeter</code> subclass to return
	 * @return singleton instance of the given subclass
	 * @throws UnsupportedImplementationException if the subclass type could
	 * not be found or instantiated
	 */
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
	
	/**
	 * Check to see if the given password satisfies the given
	 * <code>PasswordStrengthClass</code>. This is determined by running
	 * <code>iterationCount</code> on the given password and comparing it
	 * to the pre-computed minimum iteration count of the given
	 * <code>PasswordStrengthClass</code>. Note that if the password
	 * length exceeds <code>PASSWORD_LENGTH_LIMIT</code>, no check
	 * will be run and this method will automatically return <code>true</code>.
	 * @param password the password to check
	 * @param strengthClass the strength class to compare to
	 * @return <code>true</code> if the password satisfies the strength class (or
	 * the password length exceeds <code>PASSWORD_LENGTH_LIMIT</code>),
	 * <code>false</code> otherwise.
	 */
	public boolean satisfiesStrengthClass(String password, PasswordStrengthClass strengthClass) {
		BigInteger iterationCount = null;
		try {
			iterationCount = iterationCount(password, false);
		} catch(MaximumPasswordLengthExceededException lengthException) {
			// length alone will make this password satisfy any
			// standard PasswordStrengthClass
			return true;
		}
		
		return iterationCount.compareTo(strengthClass.getIterations()) >= 0;
	}
	
	/**
	 * Get the number of brute-force iterations needed to arrive at the given
	 * password. See the class description for the algorithm used to determine
	 * the count.
	 * @param passwordPlaintext the password to calculate the count for
	 * @return a <code>BigInteger</code> representing the number of iterations
	 * needed to arrive at the given password. If the password length exceeds
	 * <code>PASSWORD_LENGTH_LIMIT</code> this method will return -1.
	 */
	public BigInteger iterationCount(String passwordPlaintext) {
		try {
			return iterationCount(passwordPlaintext, false);
		} catch (MaximumPasswordLengthExceededException e) {
			return new BigInteger("-1");
		}
	}
	
	/**
	 * Get the number of brute-force iterations needed to arrive at the given
	 * password. See the class description for the algorithm used to determine
	 * the count.
	 * @param passwordPlaintext the password to calculate the count for
	 * @param bypassLengthLimitCheck true to ignore the hard-coded
	 * 
	 * @return a <code>BigInteger</code> representing the number of iterations
	 * @throws MaximumPasswordLengthExceededException if 
	 * <code>bypassLengthLimitCheck</code> is <code>true</code> and the
	 * length of <code>passwordPlaintext</code> exceeds
	 * <code>PASSWORD_LENGTH_LIMIT</code>
	 */
	public BigInteger iterationCount(String passwordPlaintext, boolean bypassLengthLimitCheck) throws MaximumPasswordLengthExceededException {
		if(null == passwordPlaintext || passwordPlaintext.length() < 1) {
			return new BigInteger("0");
		}
		
		int passwordLength = Character.codePointCount(passwordPlaintext, 0, passwordPlaintext.length());
		if(!bypassLengthLimitCheck && passwordLength > PASSWORD_LENGTH_LIMIT) {
			throw new MaximumPasswordLengthExceededException();
		}
		
		PasswordCharacterRange range = new PasswordCharacterRange(passwordPlaintext);
		BigInteger rangeSize = new BigInteger(Long.toString(range.size()));
		
		// determine number of iterations required for brute force attack
		// within this character range
		BigInteger result;
		
		BigInteger partialSumInner = rangeSize.pow(passwordLength - 1).subtract(new BigInteger("1"));
		
		BigDecimal partialSumMultiplier = new BigDecimal(range.size());
		partialSumMultiplier = partialSumMultiplier.divide(partialSumMultiplier.subtract(new BigDecimal("1")), BIG_DECIMAL_SCALE, RoundingMode.HALF_UP);
		BigDecimal partialSumResult = partialSumMultiplier.multiply(new BigDecimal(partialSumInner));
		result = partialSumResult.setScale(0, RoundingMode.HALF_UP).toBigIntegerExact();
		
		if(verifyPartialSumResult) {
			BigInteger slowResult = new BigInteger("0");
			for(int i = 1; i < passwordLength; i++) {
				BigInteger iteration = rangeSize.pow(i);
				slowResult = slowResult.add(iteration);
			}
			
			boolean resultsMatch = result.compareTo(slowResult) == 0;
			if(!resultsMatch) {
				throw new RuntimeException("Values didn't match on password with length " + passwordLength);
			}
		}
		
		for(int i = 1; i <= passwordLength; i++) {
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
	
	/**
	 * main method for running this utility from the command line.
	 * @param args
	 */
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
		BigInteger result = passwordStrengthMeter.iterationCount(password.toString());
		System.out.println(password + ": " + number.format(result));
	}
	
	/**
	 * Usage instructions for running this utility from the command line.
	 */
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
