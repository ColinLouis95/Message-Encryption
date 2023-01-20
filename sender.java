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
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public class sender{
	
	private static int buffer_size = 16 * 1024;
        private static byte[] hash;
        private static String file;
        private static Scanner input = new Scanner(System.in);
	private final String initVector = "ASDFGHJKLZXCVBNM";
	private static String symmetricKey;
	private static PublicKey rKey;

        public sender() throws IOException, NoSuchPaddingException,NoSuchProviderException, InvalidAlgorithmParameterException,
	      InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
            try{

	    	System.out.println("Enter in the file name you want encrypted ");
            	file = input.nextLine();
            	hashedMessage(file);
		initSymKey();
		aesEncryption();
		rsaEncryption();

	   }catch(IOException | InvalidKeySpecException | NoSuchAlgorithmException e){System.out.print(e);}
        }

	public String initSymKey()throws IOException{
		try{
			Path keyFile = Path.of("/home/ckugler1/Prj01/KeyGen/Keys/symmetric.key");
			symmetricKey = Files.readString(keyFile);
		}
		catch(IOException e){System.out.print(e);}
		
		return symmetricKey;
	}

	public void aesEncryption() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, 
	       InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		       System.out.println("Starting AES Encryption...");
		       try{
		       		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		       		SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
		       		cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(initVector.getBytes("UTF-8")));

            	       		BufferedInputStream inFile = new BufferedInputStream(new FileInputStream("message.dd"));
            	       		BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
            	       		byte[] buffer = new byte[buffer_size];
            	       		int bytesRead;
		       
		       		while((bytesRead = inFile.read(buffer)) != -1){
			       		byte[] output = cipher.update(buffer, 0, bytesRead);
                	       		if(output != null){
				       		outFile.write(output); 
			       		}	 
		       		}

           	       		byte[] outputBytes = cipher.doFinal();
            	       		if(outputBytes != null){
               		       		outFile.write(outputBytes);
           	      		 }
           	       		inFile.close();
       	   	       		outFile.close();
				appendMessage();
				System.out.println("Finished AES Encryption...");
		       }catch(NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | 
				       InvalidAlgorithmParameterException | IOException | IllegalBlockSizeException | BadPaddingException e){System.out.println(e);}
    }

    public void rsaEncryption() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
            IllegalBlockSizeException, BadPaddingException {
        // Grab Receiver's Public key, store it in rKey.
	System.out.println("gathering receiver's public key");
        BufferedInputStream is = new BufferedInputStream(new FileInputStream("/home/ckugler1/Prj01/KeyGen/Keys/ReceiverPublicKey.key"));
        ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(is));
        try {
            BigInteger mod = (BigInteger) ois.readObject();
            BigInteger exp = (BigInteger) ois.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod,exp);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            rKey = fact.generatePublic(keySpec);

            //ois.close();

        // RSA Encryption of "message.add-msg" with Receiver's public key
       
	   System.out.println("RSA encryption beginning");
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream("message.add-msg"));
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.rsacipher"));
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, rKey);
            byte[] buffer = new byte[117];
            int index;
	    do{
		    index = bis.read(buffer,0,buffer.length);
		    System.out.println(index);
		    bos.write(cipher.doFinal(buffer,0,buffer.length));
		    System.out.println(Arrays.toString(buffer));
		    if(index < 117){
			    byte[] last = new byte[index];
			    index = bis.read(buffer,0,last.length);
			    bos.write(cipher.doFinal(buffer,0,last.length));
		    }
	    }
	    while(index > -1);

            ois.close();
	    bis.close();
            bos.close();
            System.out.println("Finished RSA encryption of Message...");
        }catch (IOException | ClassNotFoundException | NoSuchPaddingException 
			| InvalidKeyException | NoSuchAlgorithmException e){e.printStackTrace();}

    }

	public void appendMessage() throws IOException{
		System.out.println("Appending Message...");
        	try {
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.add-msg",true));
            		byte[] buffer = new byte[buffer_size];
            		int index;
			bos.write('\n');
            		while((index = bis.read(buffer)) != -1) {
                		bos.write(buffer, 0, index);
            		}
            		bis.close();
            		bos.close();

        	} catch (IOException e) {
            		e.printStackTrace();
        	}
   	 }

        public void hashedMessage(String fileName) throws IOException, NoSuchAlgorithmException {
            try {
                BufferedInputStream file = new BufferedInputStream(new FileInputStream(fileName));
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                DigestInputStream in = new DigestInputStream(file, md);
                int index;
                byte[] buffer = new byte[buffer_size];

                do {
                    index = in.read(buffer, 0, buffer_size);

                } while (index == buffer_size);
                md = in.getMessageDigest();
                in.close();

                hash = md.digest();
		//System.out.println("DO you want to invert the 1st byte in SHA256(M)? (Y or N)");
		//String answer = input.nextLine();
		System.out.println("Hexadecimal value of hash value of the message: " +  byteToHex(hash));
           	saveHash(hash);

            }catch(IOException e){System.out.print(e);}
        
	}
	
        public void saveHash(byte[] value) throws IOException {
            try {
                BufferedOutputStream messageDigestFile = new BufferedOutputStream(new FileOutputStream("message.dd"));
                messageDigestFile.write(value, 0, value.length);
                messageDigestFile.close();
            }catch(IOException e){System.out.print(e);}
        
	}

	private String byteToHex(byte[] bytes){
		StringBuilder string = new StringBuilder();
		for (byte value: bytes){
			string.append(String.format("%02x", value));
		}
		return string.toString();
	}


	public static void main(String[] args) throws IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
		,  NoSuchPaddingException, NoSuchAlgorithmException{

		new sender();
		System.out.println(symmetricKey);
	}


}