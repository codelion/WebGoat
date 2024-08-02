package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SerializationHelper {

  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
  private static final String HMAC_ALGO = "HmacSHA256";
  private static final byte[] SECRET_KEY = "SuperSecretKey".getBytes();

  public static Object fromString(String s) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {
    byte[] dataWithHmac = Base64.getDecoder().decode(s);
    byte[] hmac = new byte[32];
    byte[] data = new byte[dataWithHmac.length - 32];
    
    System.arraycopy(dataWithHmac, 0, hmac, 0, 32);
    System.arraycopy(dataWithHmac, 32, data, 0, data.length);
    
    Mac mac = Mac.getInstance(HMAC_ALGO);
    mac.init(new SecretKeySpec(SECRET_KEY, HMAC_ALGO));
    byte[] calculatedHmac = mac.doFinal(data);
    
    for (int i = 0; i < hmac.length; i++) {
      if (calculatedHmac[i] != hmac[i]) {
        throw new SecurityException("Data integrity check failed.");
      }
    }

    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object o = ois.readObject();
    ois.close();
    return o;
  }

  public static String toString(Serializable o) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(o);
    oos.close();

    byte[] data = baos.toByteArray();
    
    Mac mac = Mac.getInstance(HMAC_ALGO);
    mac.init(new SecretKeySpec(SECRET_KEY, HMAC_ALGO));
    byte[] hmac = mac.doFinal(data);
    
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    resultStream.write(hmac);
    resultStream.write(data);
    
    return Base64.getEncoder().encodeToString(resultStream.toByteArray());
  }

  public static String show() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeLong(-8699352886133051976L);
    dos.close();
    byte[] longBytes = baos.toByteArray();
    return bytesToHex(longBytes);
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}
