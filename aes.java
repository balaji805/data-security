import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

public class aes {
    static String filePath="C:\\workarea\\DS\\AES_M13500696";
    static byte[] salt = new byte[8];
    static AlgorithmParameters params= null;

    public static String keyGen(String s) throws IOException {
        FileOutputStream fileOutputStream= null;
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        try{
            fileOutputStream= new FileOutputStream(filePath+"/key.txt");
            SecretKeyFactory factory=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 65536, 256);
            SecretKey key=factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(key.getEncoded(), "AES");
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
            System.out.println();
            objectOutputStream.writeObject(secretKey);
            return new String(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            fileOutputStream.close();
        }
        return null;
    }
    public static String toHex(String arg) {
        return String.format("%040x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
    }
    private static String encrypt(String fileName, String secretKeyPath) {
        long timestamp1=System.currentTimeMillis();
        try {
            FileInputStream fileInputStream= new FileInputStream(secretKeyPath);
            FileInputStream inFile = new FileInputStream(fileName);
            ObjectInputStream objectInputStream= new ObjectInputStream(fileInputStream);
            SecretKeySpec keySpec=(SecretKeySpec)objectInputStream.readObject();
            FileOutputStream outFile = new FileOutputStream(filePath+"/ciphertext.txt");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            AlgorithmParameters params = cipher.getParameters();
            FileOutputStream ivOutFile = new FileOutputStream("iv.txt");
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
            ivOutFile.write(iv);
            ivOutFile.close();

            byte[] input = new byte[64];
            int bytesRead;
            while ((bytesRead = inFile.read(input)) != -1) {
                byte[] output = cipher.update(input, 0, bytesRead);
                if (output != null)
                    outFile.write(output);
            }

            byte[] output = cipher.doFinal();
            if (output != null)
                outFile.write(output);
            long timestamp2=System.currentTimeMillis();
            System.out.println("timelapse for encryption using cbc::"+(timestamp2-timestamp1));
            return output.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return null;
    }
    private static String decrypt(String fileName,String secretKeyPath,String ivPath) {
        long timestamp1=System.currentTimeMillis();
        try {
            FileInputStream fis = new FileInputStream(fileName);
            FileInputStream fileInputStream= new FileInputStream(secretKeyPath);
            ObjectInputStream objectInputStream= new ObjectInputStream(fileInputStream);
            SecretKeySpec keySpec=(SecretKeySpec)objectInputStream.readObject();
            FileOutputStream fos = new FileOutputStream(filePath+"//decryptedFile.txt");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            FileInputStream ivFis = new FileInputStream(ivPath);
            byte[] iv = new byte[16];
            ivFis.read(iv);
            ivFis.close();
            cipher.init(Cipher.DECRYPT_MODE, keySpec,new IvParameterSpec(iv));
            byte[] in = new byte[64];

            int read;
            while ((read = fis.read(in)) != -1) {
                byte[] output = cipher.update(in, 0, read);
                if (output != null)
                    fos.write(output);
            }
            byte[] output = cipher.doFinal();
            if (output != null)
                fos.write(output);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }  catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        long timestamp2=System.currentTimeMillis();
        System.out.println("timelapse for decryption using cbc::"+(timestamp2-timestamp1));
        return null;
    }
    private static String encrypt_ecb(String fileName, String secretKeyPath) {
        long timestamp1=System.currentTimeMillis();
        try {
            FileInputStream fileInputStream= new FileInputStream(secretKeyPath);
            FileInputStream inFile = new FileInputStream(fileName);
            ObjectInputStream objectInputStream= new ObjectInputStream(fileInputStream);
            SecretKeySpec keySpec=(SecretKeySpec)objectInputStream.readObject();
            FileOutputStream outFile = new FileOutputStream(filePath+"/ciphertext.txt");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] input = new byte[64];
            int bytesRead;
            while ((bytesRead = inFile.read(input)) != -1) {
                byte[] output = cipher.update(input, 0, bytesRead);
                if (output != null)
                    outFile.write(output);
            }

            byte[] output = cipher.doFinal();
            if (output != null)
                outFile.write(output);
            long timestamp2=System.currentTimeMillis();
            System.out.println("timelapse for encryption using ecb::"+(timestamp2-timestamp1));
            return output.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
    private static String decrypt_ecb(String fileName,String secretKeyPath) {
        long timestamp1=System.currentTimeMillis();
        try {
            FileInputStream fis = new FileInputStream(fileName);
            FileInputStream fileInputStream= new FileInputStream(secretKeyPath);
            ObjectInputStream objectInputStream= new ObjectInputStream(fileInputStream);
            SecretKeySpec keySpec=(SecretKeySpec)objectInputStream.readObject();
            FileOutputStream fos = new FileOutputStream(filePath+"//decryptedFile1.txt");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] in = new byte[64];

            int read;
            while ((read = fis.read(in)) != -1) {
                byte[] output = cipher.update(in, 0, read);
                if (output != null)
                    fos.write(output);
            }
            byte[] output = cipher.doFinal();
            if (output != null)
                fos.write(output);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }  catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        long timestamp2=System.currentTimeMillis();
        System.out.println("timelapse for decryption using ecb::"+(timestamp2-timestamp1));
        return null;
    }

    public static void main(String[] args) {
        try {
            System.out.println("secret key(256 bits) in hexadecimal format:: "+toHex(keyGen("IamBALAJI")));
            for(int i =1;i<6;i++) {
                System.out.println("Encrypted data1:: " + toHex(encrypt(filePath + "/plaintext.txt", filePath + "/key.txt")));
                decrypt(filePath+"/ciphertext.txt",filePath+"/key.txt",filePath+"/iv.txt");
            }
            for(int i =1;i<6;i++) {
                System.out.println("Encrypted data2:: " + toHex(encrypt_ecb(filePath + "/plaintext.txt", filePath + "/key.txt")));
                decrypt_ecb(filePath+"/ciphertext1.txt",filePath+"/key.txt");
            }


            decrypt(filePath+"/ciphertext.txt",filePath+"/key.txt",filePath+"/iv.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }




}
