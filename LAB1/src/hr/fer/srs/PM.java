package hr.fer.srs;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * razred koji obavalja zadatak Password Manager-a kako je opisan u zadatku.
 * @author Antonio
 *
 */
public class PM {
	//Korišteni algoritam
	private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
	//preporucena velicina za GCM
	private static final int TAG_LENGTH_BIT = 128;
	//master pass
	private static String MASTER_PASS = "MasterPsw";

	public static void main(String[] args) throws Exception {
		//ako je ulaz init
		if (args[0].equals("init")) {
			if(args.length!=2)
				System.out.println("For init you only need MasterPass as argument.");
			if (!args[1].equals(MASTER_PASS)) {
				System.out.println("Master password incorrect or integrity check failed.");
				return;
			}
			//kreiraj file 0036524183.tx ako ne postoji ili kreiraj novi koji je prazan; u njega cemo upisivati kriptirane parove
			try {
				File file = new File("0036524183.txt");
				boolean isFileCreated = file.createNewFile();
				if(!isFileCreated) {
					file.delete();
					isFileCreated = file.createNewFile();
				}
				System.out.println("Password manager initialized.");
			} catch (IOException e) {
				e.printStackTrace();
			}
		//put
		} else if (args[0].equals("put")) {
			if(args.length!=4)
				System.out.println("For put you need MasterPass, web adress and password as arguments.");
			if (!args[1].equals(MASTER_PASS)) {
				System.out.println("Master password incorrect or integrity check failed.");
				return;
			}
			
			//Provjeri postoji li vec sifra za zadanu adresu
			Map<String, String> map = new HashMap<>();
			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();

				while (line != null) {
					String decrypted = decrypt(line, MASTER_PASS);
					String[] splits=decrypted.split("#");
					map.put(splits[0].substring(1), splits[1].substring(0, splits[1].length()-1));
					line = reader.readLine();
				}
				//ako postoji
				if(map.get(args[2]) != null) {
					//prvo prebrsi sve
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
					//onda ponovo upisi sve s novom sifrom za tu adresu
					map.put(args[2], args[3]);
					
					for(Map.Entry<String, String> ent: map.entrySet()) {
						//klasicno formatiranje zapisa {adresa#sifra}
						String zapis = "{" + ent.getKey() + "#" + ent.getValue() + "}";
						try (BufferedWriter writer = new BufferedWriter(new FileWriter("0036524183.txt",StandardCharsets.UTF_8, true))) {
							String encrypted = encrypt(zapis.getBytes(StandardCharsets.UTF_8), MASTER_PASS);

							writer.append(encrypted+"\n");
						} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
								| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
								| InvalidKeySpecException | IOException e) {
							e.printStackTrace();
						}
					}
					System.out.println("Stored password for "+ args[2]+".");
				}
				//ako nepostoji
				else {
					//klasicno formatiranje zapisa {adresa#sifra}
					String zapis = "{" + args[2] + "#" + args[3] + "}";
					try (BufferedWriter writer = new BufferedWriter(new FileWriter("0036524183.txt",StandardCharsets.UTF_8, true))) {
						String encrypted = encrypt(zapis.getBytes(StandardCharsets.UTF_8), MASTER_PASS);

						writer.append(encrypted+"\n");
						System.out.println("Stored password for "+ args[2]+".");
					} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
							| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
							| InvalidKeySpecException | IOException e) {
						e.printStackTrace();
					}
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
			
		//get
		} else if (args[0].equals("get")) {
			if(args.length!=3)
				System.out.println("For get you only need MasterPass and web adress as arguments.");
			if (!args[1].equals(MASTER_PASS)) {
				System.out.println("Master password incorrect or integrity check failed.");
				return;
			}
			Map<String, String> map = new HashMap<>();
			try (BufferedReader reader = new BufferedReader(new FileReader("0036524183.txt", StandardCharsets.UTF_8))) {
				String line = reader.readLine();

				while (line != null) {
					String decrypted = decrypt(line, MASTER_PASS);
					String[] splits=decrypted.split("#");
					map.put(splits[0].substring(1), splits[1].substring(0, splits[1].length()-1));
					line = reader.readLine();
				}
				
				if(map.get(args[2]) != null) {
					System.out.println("Password for "+args[2]+" is: "+ map.get(args[2])+".");
				}
				else {
					System.out.println("There is no password stored for "+args[2]+".");
				}
			} catch(Exception e) {
				e.printStackTrace();
			}

		} else {
			System.out.println("Wrong arguments, try again(init, put or get)");
		}
	}
	/**
	 * Funkcija za enkripciju zapisa
	 * @param pText plainText zapisan u polju bitova
	 * @param password Master password
	 * @return vraca enkriptiranu verziju zapisa
	 * @throws Exception
	 */
	public static String encrypt(byte[] pText, String password) throws Exception {
		//salt i iv velicine 16 bajtova
		byte[] salt = getBytes();
		byte[] iv = getBytes();
		//generiranje tajnog AES kljuca iz naše master šifre
		SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
		Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
		cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
		byte[] cipherText = cipher.doFinal(pText);
		// prefix IV i Salt na sifrirani tekst
		byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length).put(iv).put(salt)
				.put(cipherText).array();
		// string reprezentacija u base64
		return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);

	}
	/**
	 * 
	 * @param cText šifrirani tekst
	 * @param password master pass
	 * @return dekriptirani cText
	 * @throws Exception
	 */
	private static String decrypt(String cText, String password) throws Exception {

		byte[] decode = Base64.getDecoder().decode(cText.getBytes(StandardCharsets.UTF_8));
		// uzmi iv i salt iz polja bajtova
		ByteBuffer bb = ByteBuffer.wrap(decode);
		byte[] iv = new byte[16];
		bb.get(iv);
		byte[] salt = new byte[16];
		bb.get(salt);
		byte[] cipherText = new byte[bb.remaining()];
		bb.get(cipherText);
		//ponovno generiranje istog tajnog AES kljuca iz naše master šifre
		SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
		Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
		cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
		byte[] plainText = cipher.doFinal(cipherText);
		return new String(plainText, StandardCharsets.UTF_8);

	}
	
	/**
	 * Generiranje AES kljuca iz željene šifre
	 * @param password master pass
	 * @param salt salt koji je dodan na tekst
	 * @return {@link SecretKey} koji koristimo
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		//najvise moguce ponavljanja i najveca moguca velicina kljuca za bolju sigurnost
		int iterationCount = 65536;
		int keyLength = 256;
		KeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		return secret;
	}
	/**
	 * Function for generating byte arrays of size 16 for salt and iv
	 * @return
	 */
	public static byte[] getBytes() {
		byte[] bytes = new byte[16];
		new SecureRandom().nextBytes(bytes);
		return bytes;
	}
}
