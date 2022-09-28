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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*
 * Login funcition of our system.
 * 
 */
public class login {
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		if (args.length != 1) {
			System.out.println("Wrong arguments");
			return;
		}
		String user = args[0];

		Console cnsl = System.console();

		boolean tocno = false;
		boolean force = false;
		String zapis = "";
		String password ="";
		while (!tocno) {

			char[] pass = cnsl.readPassword("Password: ");
			password = String.valueOf(pass);

			zapis = "";
			force = false;

			// Read from file
			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();
				boolean zapisan = false;

				while (line != null) {
					if (line.contains(user)) {
						if (line.endsWith("force")) {
							force = true;
						}
						zapisan = true;
						zapis = line;
						break;
					}
					line = reader.readLine();
				}
				if (!zapisan) {
					System.out.println("Username or password incorrect.");
					return;
				}

			} catch (IOException e) {
				e.printStackTrace();
			}
			// check pass

			String[] splits = zapis.split("#");

			byte[] salt = fromHex(splits[1]);
			byte[] hash = fromHex(splits[2]);

			tocno = validiraj(salt, hash, password);

			if (!tocno) {
				System.out.println("Username or password incorrect.");
			}

		}
		// provjeri za false
		if (force) {

			char[] newPass = cnsl.readPassword("New password: ");

			char[] repeatNewPass = cnsl.readPassword("Repeat new password: ");

			String newPassword = String.valueOf(newPass);
			String repeatPassword = String.valueOf(repeatNewPass);

			if (!(newPassword.equals(repeatPassword))) {
				System.out.println("New passwords aren't matching.");
				return;
			}

			// sad mozemo spremat
			// zapis je user+salt+hash pass
			zapis = user + "#" + generateHash(newPassword);

			// kreiraj file 0036524183.txt ako ne postoji

			List<String> zapisi = new LinkedList<>();

			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();

				while (line != null) {
					if (line.startsWith(user) && line.contains(user)) {
						line = reader.readLine();
						continue;
					}
					zapisi.add(line);
					line = reader.readLine();
				}
			}

			// prebris sve
			try {
				File file = new File("0036524183.txt");
				boolean isFileCreated = file.createNewFile();
				if (!isFileCreated) {
					file.delete();
					isFileCreated = file.createNewFile();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

			try (BufferedWriter writer = new BufferedWriter(
					new FileWriter("0036524183.txt", StandardCharsets.UTF_8, true))) {
				writer.append(zapis + "\n");
				for (String str : zapisi) {
					writer.append(str + "\n");
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		System.out.println("Login was succesful");

	}

	/**
	 * Validation function for of pass.
	 * 
	 * @param salt
	 * @param hash
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static boolean validiraj(byte[] salt, byte[] hash, String password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		int iterations = 65536;
		int keyLength = 128;
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] testHash = skf.generateSecret(spec).getEncoded();
		return Arrays.equals(hash, testHash);

	}

	/**
	 * Turns hex string to byte array.
	 * 
	 * @param hex
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
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
		int keyLength = 128;
		char[] chars = password.toCharArray();
		byte[] salt = getBytes();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, keyLength);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

		byte[] hash = skf.generateSecret(spec).getEncoded();
		return toHex(salt) + "#" + toHex(hash);

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
}
