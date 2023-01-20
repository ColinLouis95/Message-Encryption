import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Scanner;
import java.security.*;
import java.io.*;
import java.util.Collections;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.DigestInputStream;

public class receiver{
	private PrivateKey rKey;
	private String file;
	private Scanner input = new Scanner(System.in);
	private String symmetricKey;
	private final String initVector = "ASDFGHJKLZXCVBNM";

	public receiver() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
	       IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException, BadPaddingException{
		System.out.println("Input the name of the message file: ");
	        file = input.nextLine();	
		rsaDecryption();
		initSymKey();
		aesDecryption();
		compareDigest();
	}

	public String initSymKey() throws IOException{
		try{
			Path keyFile = Path.of("/home/ckugler1/Prj01/KeyGen/Keys/symmetric.key");
			symmetricKey = Files.readString(keyFile);
		}catch(IOException e){System.out.println(e);}
		return symmetricKey;
	}

	public String byteArrayToHex(byte[] array){
		StringBuilder build = new StringBuilder(array.length * 2);
	       	for(byte a: array){
			build.append(String.format("%02x", a));
		}
		return build.toString();
	}

	public void compareDigest() throws IOException, NoSuchAlgorithmException{
		try{

			FileInputStream fis = new FileInputStream(file);
			byte[] buffer = new byte[16 * 1024];
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			DigestInputStream in = new DigestInputStream(fis,md);
			int index;

			do{
				index = in.read(buffer,0,buffer.length);
			}while(index == buffer.length);
			md = in.getMessageDigest();
			in.close();
			byte[] hash = md.digest();
			System.out.println("digital digest of " + file + " is: " + byteArrayToHex(hash));
		}catch(IOException e){System.out.println(e);}
	}

	public void aesDecryption() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
	       BadPaddingException{
		try{

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding","SunJCE");
			SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initVector.getBytes("UTF-8")));

			FileInputStream fis = new FileInputStream("/home/ckugler1/Prj01/Sender/message.add-msg");
			BufferedOutputStream bos1 = new BufferedOutputStream(new FileOutputStream("message.dd"));
			BufferedOutputStream bos2 = new BufferedOutputStream(new FileOutputStream(file));
			byte[] srcfile = Files.readAllBytes(Paths.get("/home/ckugler1/Prj01/Sender/message.add-msg"));
			byte[] add = new byte[32];
			int num = srcfile.length;
			byte[] message = new byte[num];
			
			System.arraycopy(srcfile,0,add,0,32);
			System.arraycopy(srcfile,33,message,0,num - 33);

			bos1.write(cipher.doFinal(add,0,add.length));
			System.out.println("authentic digital digest Hex: " + byteArrayToHex(add));
		//	System.out.println(Arrays.toString(add));

			bos2.write(message,0,message.length);
		//	for(int i = 0; i < 32; i++){

			//byte[] buffer = new byte[32];
		//	int bytesRead;
		//	int index;
		//	while((index = fis.read(buffer)) != -1)
		//	byte[] add = new byte[fis.read(buffer)];
		//	System.out.print(Arrays.toString(add));
		
		//	bos1.write(cipher.doFinal(add,0,add.length));
		//	System.out.println(cipher.doFinal(add,0,add.length));
		//	fis.skip(32);
		//	while((bytesRead = fis.read(buffer)) != -1){
		//		bos2.write(buffer,0,buffer.length);
		//	}
			fis.close();
			bos1.close();
			bos2.close();
		}catch(NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | 
				InvalidAlgorithmParameterException | IOException /*| IllegalBlockSizeException | BadPaddingException*/ e){System.out.println(e);}

	
	}


	 public void rsaDecryption() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
            IllegalBlockSizeException, BadPaddingException {
        // Grab Receiver's Private key, store it in rKey.
	System.out.println("gathering receiver's private key");
        BufferedInputStream is = new BufferedInputStream(new FileInputStream("/home/ckugler1/Prj01/KeyGen/Keys/ReceiverPrivateKey.key"));
        ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(is));
        try {
            BigInteger mod = (BigInteger) ois.readObject();
            BigInteger exp = (BigInteger) ois.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod,exp);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            rKey = fact.generatePrivate(keySpec);

        // RSA Decryption of "message.rsacipher" with Receiver's private key

	    System.out.println("RSA decryption beginning");
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream("/home/ckugler1/Prj01/Sender/message.rsacipher"));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rKey);
            byte[] buffer = new byte[128];
            int index;
	    do{
		    index = bis.read(buffer,0,buffer.length);
		    System.out.println(index);
		    bos.write(cipher.doFinal(buffer,0,buffer.length));
		    System.out.println(Arrays.toString(buffer));
		    if(index <= 128 && index > -1){
			    byte[] last = new byte[index];
			    index = bis.read(buffer,0,buffer.length);
			    System.out.println("Index at index <= 128: " + index);
			    bos.write(cipher.doFinal(buffer,0,buffer.length));
		    }
	    }
	    while(index == 128);

            ois.close();
	    bis.close();
            bos.close();
            System.out.println("Finished RSA decryption of Message...");
        }catch (IOException | ClassNotFoundException | NoSuchPaddingException
			| InvalidKeyException | NoSuchAlgorithmException e){e.printStackTrace();}

    }

    public static void main(String[] args) throws IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException{
		new receiver();
	}


}