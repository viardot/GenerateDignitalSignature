import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.channels.SeekableByteChannel;
import java.nio.ByteBuffer;

import java.io.IOException;
import java.security.*;

public class GenSig {

  public static void main(String[] args) {
    if (args.length != 1) {
      System.out.println("Usage: GenSig nameOfFileToSign");
      return;
    }
    try {
      
      //Get key generator object
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
      keyGen.initialize(1024, random);
      
      //Generate the key pair
      KeyPair pair    = keyGen.generateKeyPair();
      PrivateKey priv = pair.getPrivate();
      PublicKey pub   = pair.getPublic();

      //Get a Signature object
      Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
      dsa.initSign(priv);

      //Read data from file
      Path file = Paths.get(args[0]); 
      try (SeekableByteChannel sbc = Files.newByteChannel(file)) {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
	while (sbc.read(buffer) > 0) {
          buffer.flip();
	  dsa.update(buffer);
	  buffer.clear();
	}
      } catch (IOException e) {
        System.err.println("Error reading file");
	e.printStackTrace();
      }

      //Save the signature file
      byte[] realSig = dsa.sign();
      file = Paths.get("sig");
      ByteBuffer buffer = ByteBuffer.wrap(realSig);
      try (SeekableByteChannel sigSBC = Files.newByteChannel(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.APPEND)) {
        sigSBC.write(buffer);
      } catch (IOException e) {
        System.out.println("Error writing signed file");
	e.printStackTrace();
      } 


      //Save the public key file
      byte[] key = pub.getEncoded();
      file = Paths.get("myPubKey");
      buffer = ByteBuffer.wrap(key);
      try (SeekableByteChannel keySBC = Files.newByteChannel(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.APPEND)) {
        keySBC.write(buffer);
      } catch (IOException e) {
        System.out.println("Error writing public key file");
	e.printStackTrace();
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
