package hr.fer.srs.lab2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Admin applicacion for adding users, changing passwords, forcin pass changes and deleting users.
 * @author Antonio
 *
 */
public class usermgmt {
	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		if (args.length != 2) {
			System.out.println("Wrong arguments");
			return;
		}

		if (args[0].equals("add")) {

			Console cnsl = System.console();
			char[] pass = cnsl.readPassword("Password: ");
			char[] repeatPass = cnsl.readPassword("Repeat password: ");

			String password = String.valueOf(pass);
			String repeatPassword = String.valueOf(repeatPass);
			
			if (!(password.equals(repeatPassword))) {
				System.out.println("User add failed. Password mismatch.");
				return;
			}
			 
			String user = args[1];
			
			// sad mozemo spremat
			// zapis je user+salt+hash pass
			String zapis = user+ "#"+ generateHash(password);
			
			//kreiraj file 0036524183.txt ako ne postoji 
			File file = new File("0036524183.txt");
			boolean exists = file.exists();
			if(!exists) {
				boolean created=file.createNewFile();
			}
			
			//appendaj zapis u novi red
			try (BufferedWriter writer = new BufferedWriter(new FileWriter("0036524183.txt",StandardCharsets.UTF_8, true))) {
				writer.append(zapis+"\n");
			} catch ( IOException e) {
				e.printStackTrace();
			}
			
			System.out.println("User "+user+" successfuly added.");
			
		} else if (args[0].equals("passwd")) {
			Console cnsl = System.console();
			char[] pass = cnsl.readPassword("Password: ");

			char[] repeatPass = cnsl.readPassword("Repeat password: ");

			String password = String.valueOf(pass);
			String repeatPassword = String.valueOf(repeatPass);
			
			if (!(password.equals(repeatPassword))) {
				System.out.println("Password change failed. Password mismatch.");
				return;
			}
			 
			String user = args[1];
			
			// sad mozemo spremat
			// zapis je user+salt+hash pass
			String zapis = user + "#"+ generateHash(password);
			
			//kreiraj file 0036524183.txt ako ne postoji 
			
			
			List<String> zapisi=new LinkedList<>();
						
			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();

				while(line!=null) {
					if(line.startsWith(user) && line.contains(user)) {
						line=reader.readLine();
						continue;
					}
					zapisi.add(line);
					line=reader.readLine();
				}
			}
			
			//prebris sve
			try {
				File file = new File("0036524183.txt");
				boolean isFileCreated = file.createNewFile();
				if(!isFileCreated) {
					file.delete();
					isFileCreated = file.createNewFile();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			try (BufferedWriter writer = new BufferedWriter(new FileWriter("0036524183.txt",StandardCharsets.UTF_8, true))) {
				writer.append(zapis+"\n");
				for(String str: zapisi) {
					writer.append(str+"\n");
				}
			} catch ( IOException e) {
				e.printStackTrace();
			}
			
			System.out.println("Password succesfully changed.");

		} else if (args[0].equals("forcepass")) {
			
			String user = args[1];
						
			//kreiraj file 0036524183.txt ako ne postoji 
			
			
			List<String> zapisi=new LinkedList<>();
						
			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();

				while(line!=null) {
					if(line.startsWith(user) && line.contains(user)) {
						zapisi.add(line+"#"+"force");
						line=reader.readLine();
						continue;
					}
					zapisi.add(line);
					line=reader.readLine();
				}
			}
			
			//prebris sve
			try {
				File file = new File("0036524183.txt");
				boolean isFileCreated = file.createNewFile();
				if(!isFileCreated) {
					file.delete();
					isFileCreated = file.createNewFile();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			try (BufferedWriter writer = new BufferedWriter(new FileWriter("0036524183.txt",StandardCharsets.UTF_8, true))) {
				
				for(String str: zapisi) {
					writer.append(str+"\n");
				}
			} catch ( IOException e) {
				e.printStackTrace();
			}
			
			System.out.println("User will be requested to change password on next login.");
			
			
		} else if (args[0].equals("del")) {
			String user = args[1];
			
			//kreiraj file 0036524183.txt ako ne postoji 
			
			
			List<String> zapisi=new LinkedList<>();
						
			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();

				while(line!=null) {
					if(line.startsWith(user) && line.contains(user)) {
						line=reader.readLine();
						continue;
					}
					zapisi.add(line);
					line=reader.readLine();
				}
			}
			
			//prebris sve
			try {
				File file = new File("0036524183.txt");
				boolean isFileCreated = file.createNewFile();
				if(!isFileCreated) {
					file.delete();
					isFileCreated = file.createNewFile();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			try (BufferedWriter writer = new BufferedWriter(new FileWriter("0036524183.txt",StandardCharsets.UTF_8, true))) {
				
				for(String str: zapisi) {
					writer.append(str+"\n");
				}
			} catch ( IOException e) {
				e.printStackTrace();
			}
			
			System.out.println("User successfuly removed.");
		}
		else {
			System.out.println("Wrong arguments");
		}

	}
	/**
	 * Gnerates hashed pass in hex.
	 * 
	 * @param password
	 * @return
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	private static String generateHash(String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
		int iterations = 65536;
		int keyLength=128;
		char[] chars = password.toCharArray();
		byte[] salt = getBytes();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, keyLength);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

		byte[] hash = skf.generateSecret(spec).getEncoded();
		return toHex(salt) + "#" + toHex(hash);

	}
	/**
	 * Generates new byte array, size 16.
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] getBytes() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt;
	}
	/**
	 * Turn byte arrays to strings.
	 * 
	 * @param array
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static String toHex(byte[] array) throws NoSuchAlgorithmException {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);

		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0) {
			return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
			return hex;
		}
	}

}
