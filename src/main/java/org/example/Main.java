package org.example;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.TreeSet;


public class Main {
    public static void RSA_KEY_Generator() throws IOException, NoSuchAlgorithmException {
        // --- we need a key pair to test encryption/decryption
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair  pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        // 將public key 保存在文件中
        try (FileOutputStream fos = new FileOutputStream("publicKey")) {
            fos.write(publicKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        File publicKeyFile = new File("publicKey");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        // 將private key 保存在文件中
        try (FileOutputStream fos = new FileOutputStream("privateKey")) {
            fos.write(privateKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static PrivateKey getPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    public static PublicKey getPublicKey(String filename) throws Exception {
        // getting byte data of private key
        byte[] publicKeyBytes = Files.readAllBytes(new File(filename).toPath());
        // creating keyspec object
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        // creating object of keyfactory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // generating private key from the provided key spec and return
        return keyFactory.generatePublic(publicKeySpec);
    }
    public static byte[] RSA_OAEP_Encrypt(String plainText, PublicKey publicKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        oaepFromAlgo.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ct = oaepFromAlgo.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return ct;
    }
    public static String RSA_OAEP_Decrypt(byte[] cipherText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] pt = oaepFromInit.doFinal(cipherText);
        return new String(pt, StandardCharsets.UTF_8);
    }
    public static byte[] RSA_Encrypt(String plainText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher normalRSA = Cipher.getInstance("RSA/ECB/NoPadding");
        normalRSA.init(Cipher.ENCRYPT_MODE, publicKey);
        return normalRSA.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }
    public static String RSA_Decrypt(byte[] cipherText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher normalRSA_d = Cipher.getInstance("RSA/ECB/NoPadding");
        normalRSA_d.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] normal_pt = normalRSA_d.doFinal(cipherText);
        return new String(normal_pt, StandardCharsets.UTF_8);
    }
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] RSA_PSS_Sign_String(String message, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        //https://www.yiibai.com/java_cryptography/java_cryptography_verifying_signature.html
        Signature sign = Signature.getInstance("SHA1withRSA/PSS");
        sign.initSign(privateKey);
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        sign.update(bytes);
        return sign.sign();
    }
    public static boolean RSA_PSS_Verify_String(byte[] signature, String message,PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA1withRSA/PSS");
        sign.initVerify(publicKey);
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        sign.update(bytes);
        return sign.verify(signature);
    }


    public static void main(String argv[]) throws Exception {
        // add provider only if it's not in the JVM
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        //RSA_KEY_Generator();
        PublicKey publicKey = getPublicKey("publicKey");
        PrivateKey privateKey = getPrivateKey("privateKey");

        byte[] cipherText;
        cipherText = RSA_OAEP_Encrypt("盧柏諭、RBYN圻、林君諺、李昱佑", publicKey);
        System.out.println(bytesToHex(cipherText));
        System.out.println(RSA_OAEP_Decrypt(cipherText, privateKey));

        cipherText = RSA_Encrypt("盧柏諭、RBYN圻、林君諺、李昱佑", publicKey);
        System.out.println(bytesToHex(cipherText));
        System.out.println(RSA_Decrypt(cipherText, privateKey));


        byte[] signature = RSA_PSS_Sign_String("盧柏諭、RBYN圻、林君諺、李昱佑", privateKey);
        System.out.println(bytesToHex(signature));
        System.out.println(RSA_PSS_Verify_String(signature, "盧柏諭、RBYN圻、林君諺、李昱佑", publicKey));
    }
}
/*
TreeSet<String> algorithms = new TreeSet<>();

        Provider[] providers = Security.getProviders();
        System.out.println("-----Provider 列表如下：-----");
        for (Provider provider : providers) {
            System.out.println(provider.getName());
        }

        System.out.println("-----支持的签名算法如下：-----");

        for (Provider provider : providers) {
            for (Provider.Service service : provider.getServices())
                if (service.getType().equals("Signature")) {
                    algorithms.add(service.getAlgorithm());
                }
        }

        for (String algorithm : algorithms) {
            System.out.println(algorithm);
        }
 */