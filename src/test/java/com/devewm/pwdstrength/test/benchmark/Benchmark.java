package com.devewm.pwdstrength.test.benchmark;

import java.math.BigInteger;
import java.text.DecimalFormat;

import com.devewm.pwdstrength.PasswordStrengthMeter;

public class Benchmark {
	public static final long RUN_TIME_MS = 30000;
	
	public static BigInteger bench(long timelimit) {
		PasswordStrengthMeter meter = PasswordStrengthMeter.getInstance();
		BigInteger result = new BigInteger("0");
		BigInteger incrementor = new BigInteger("1");
		long startTime = System.currentTimeMillis();
		boolean timeExceeded = false;
		
		int spread = 64;
		while(!timeExceeded) {
			
			String password = new String(Character.toChars(1));
			for(int i = 1; i < PasswordStrengthMeter.PASSWORD_LENGTH_LIMIT; i++) {
				password += new String(Character.toChars(i * spread));
			}
			
			meter.iterationCount(password);
			result = result.add(incrementor);
			timeExceeded = System.currentTimeMillis() >= startTime + timelimit;
			
			spread++;
			if(spread >= Math.ceil((double) Character.MAX_CODE_POINT / PasswordStrengthMeter.PASSWORD_LENGTH_LIMIT)) {
				spread = 1;
			}
			
		}
		
		return result;
	}
	
	public static void main(String[] args) {
		System.out.println("Starting benchmark, will run for " + RUN_TIME_MS + "ms...");
		BigInteger result = bench(RUN_TIME_MS);
		System.out.println("Done.");
		
		DecimalFormat number = new DecimalFormat();
		number.setGroupingUsed(true);
		System.out.println("Number of passwords checked: " + number.format(result));
	}
}
