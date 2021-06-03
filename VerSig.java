import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.channels.SeekableByteChannel;
import java.nio.ByteBuffer;

import java.io.IOException;
import java.security.*;
import java.security.spec.*;

public class VerSig {

  public static void main (String[] args) {
    if (args.length != 3) {
      System.out.println("Usage: VerSig <public key> <signature> <data>");
      return;
    }
    try{
      
      byte[] encKey = readFile(args[0]);

      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
      KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
      PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
      
      System.out.println("Public key information");
      System.out.printf("-Algorithm \t%s\n", pubKey.getAlgorithm());
      System.out.printf("-Format \t%s\n", pubKey.getFormat());

      byte[] sigToVerify = readFile(args[1]);

      Signature sig  = Signature.getInstance("SHA1withDSA", "SUN");
      sig.initVerify(pubKey);
      
      Path file = Paths.get(args[2]);
      try (SeekableByteChannel sbc = Files.newByteChannel(file)){
        ByteBuffer buffer = ByteBuffer.allocate(1024);
	while(sbc.read(buffer) > 0) {
          buffer.flip();
          sig.update(buffer);
	  buffer.clear();
	}
      } catch (IOException e) {
        System.err.println("Error reading data file");
	e.printStackTrace();
      }
      boolean verifies = sig.verify(sigToVerify);

      System.out.println("signature verifies: " + verifies);

    } catch (InvalidKeySpecException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      e.printStackTrace();
    }
  }

  private static byte[] readFile(String fileName) {
    Path file = Paths.get(fileName);
      byte[] byteArray  = null;
      try {
        byteArray = Files.readAllBytes(file);
      } catch (IOException e) {
        System.err.println("Error reading file");
	e.printStackTrace();
      }
    return byteArray;
  }
}
