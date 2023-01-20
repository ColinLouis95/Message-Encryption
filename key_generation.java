import java.io.*;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;
import java.util.Scanner;

public class key_generation{
        public void saveToFile(String fileName, BigInteger modValue, BigInteger expValue) throws IOException {
            System.out.println("Writing to File " + fileName);
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
            try{
                out.writeObject(modValue);
                out.writeObject(expValue);
            } catch (Exception e){
                try {
                    throw new IOException("OPERATION FAILED", e);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }finally{
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public key_generation() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
            /* This section is for the sender's public and private key */
            SecureRandom random1 = new SecureRandom();
            KeyPairGenerator generator1 = KeyPairGenerator.getInstance("RSA");
            generator1.initialize(1024,random1);

            KeyPair sendpair = generator1.generateKeyPair();
            Key sendPubKey = sendpair.getPublic();
            Key sendPrivKey = sendpair.getPrivate();

            
	    /* This section is for the receiver's public and private key */

            SecureRandom random2 = new SecureRandom();
            KeyPairGenerator generator2 = KeyPairGenerator.getInstance("RSA");
            generator2.initialize(1024,random2);

            KeyPair receivepair = generator2.generateKeyPair();
            Key receivePubKey = receivepair.getPublic();
            Key receivePrivKey = receivepair.getPrivate();

            
	    /* set factory to be used by public/private keys. */

            KeyFactory factory = KeyFactory.getInstance("RSA");

            
	    /* create and save sender's public and private keys to respective files */
            
	    RSAPublicKeySpec sendPubKSpec = factory.getKeySpec(sendPubKey,RSAPublicKeySpec.class);
            RSAPrivateKeySpec sendPrivKSpec = factory.getKeySpec(sendPrivKey,RSAPrivateKeySpec.class);
            saveToFile("Keys/SenderPublicKey.key", sendPubKSpec.getModulus(), sendPubKSpec.getPublicExponent());
            saveToFile("Keys/SenderPrivateKey.key", sendPrivKSpec.getModulus(), sendPrivKSpec.getPrivateExponent());

            
	    /*create and save recevier's public and private keys to respective files */
            
	    RSAPublicKeySpec recPubKSpec = factory.getKeySpec(receivePubKey,RSAPublicKeySpec.class);
            RSAPrivateKeySpec recPrivKSpec = factory.getKeySpec(receivePrivKey,RSAPrivateKeySpec.class);
            saveToFile("Keys/ReceiverPublicKey.key", recPubKSpec.getModulus(), recPubKSpec.getPublicExponent());
            saveToFile("Keys/ReceiverPrivateKey.key", recPrivKSpec.getModulus(), recPrivKSpec.getPrivateExponent());

	    Scanner input = new Scanner(System.in);
	    System.out.println("Enter in a 16 character string: ");
	    String symmetricKey = input.nextLine();
	    createSymKey(symmetricKey);
        }

	private void createSymKey(String key) throws IOException {
		BufferedOutputStream outFile = new BufferedOutputStream(new FileOutputStream("Keys/symmetric.key"));
		byte[] keyBytes = key.getBytes("UTF-8");
		outFile.write(keyBytes,0,keyBytes.length);
		outFile.close();
	}


        public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
            new key_generation();
	    
        }
    }



                                                                                                                                                                                                                                                            1,5           Top
