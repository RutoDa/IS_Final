package org.example;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;


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
    public static byte[] RSA_OAEP_Encrypt_String(String plainText, PublicKey publicKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        oaepFromAlgo.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ct = oaepFromAlgo.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return ct;
    }
    public static String RSA_OAEP_Decrypt_Byte(byte[] cipherText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] pt = oaepFromInit.doFinal(cipherText);
        return new String(pt, StandardCharsets.UTF_8);
    }
    public static byte[] RSA_OAEP_Encrypt_SignFirst(byte[] plainText, PublicKey publicKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        oaepFromAlgo.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] pt1 = Arrays.copyOfRange(plainText, 0, 62);
        byte[] pt2 = Arrays.copyOfRange(plainText, 62, 124);
        byte[] pt3 = Arrays.copyOfRange(plainText, 124,128);

        byte[] ct1 = oaepFromAlgo.doFinal(pt1);
        byte[] ct2 = oaepFromAlgo.doFinal(pt2);
        byte[] ct3 = oaepFromAlgo.doFinal(pt3);
        byte[] ct = new byte[ct1.length + ct2.length + ct3.length];  //resultant array of size first array and second array
        System.arraycopy(ct1, 0, ct, 0, ct1.length);
        System.arraycopy(ct2, 0, ct, ct1.length, ct2.length);
        System.arraycopy(ct3, 0, ct, ct1.length+ct2.length, ct3.length);
        return ct;
    }
    public static byte[] RSA_OAEP_Decrypt_SignFirst(byte[] cipherText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);

        byte[] ct1 = Arrays.copyOfRange(cipherText, 0, 128);
        byte[] ct2 = Arrays.copyOfRange(cipherText, 128, 256);
        byte[] ct3 = Arrays.copyOfRange(cipherText, 256,384);

        byte[] pt1 = oaepFromInit.doFinal(ct1);
        byte[] pt2 = oaepFromInit.doFinal(ct2);
        byte[] pt3 = oaepFromInit.doFinal(ct3);
        byte[] pt = new byte[pt1.length + pt2.length + pt3.length];
        System.arraycopy(pt1, 0, pt, 0, pt1.length);
        System.arraycopy(pt2, 0, pt, pt1.length, pt2.length);
        System.arraycopy(pt3, 0, pt, pt1.length+pt2.length, pt3.length);
        //byte[] pt = oaepFromInit.doFinal(cipherText.getBytes(StandardCharsets.UTF_8));
        return pt;
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
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    public static byte[] RSA_PSS_Sign_String(String message, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        //https://www.yiibai.com/java_cryptography/java_cryptography_verifying_signature.html
        Signature sign = Signature.getInstance("SHA1withRSA/PSS");
        sign.initSign(privateKey);
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        sign.update(bytes);
        return sign.sign();
    }
    public static byte[] RSA_PSS_Sign_Byte(byte[] message, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        //https://www.yiibai.com/java_cryptography/java_cryptography_verifying_signature.html
        Signature sign = Signature.getInstance("SHA1withRSA/PSS");
        sign.initSign(privateKey);
        byte[] bytes = message;
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
    public static boolean RSA_PSS_Verify_Byte(byte[] signature, byte[] message,PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA1withRSA/PSS");
        sign.initVerify(publicKey);
        byte[] bytes = message;
        sign.update(bytes);
        return sign.verify(signature);
    }
    private static void createAndShowGUI() throws Exception {
        // 创建 JFrame 实例
        JFrame frame = new JFrame("Test");
        // Setting the width and height of frame
        frame.setSize(350, 800);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JPanel panel = new JPanel();
        // 添加面板
        frame.add(panel);
        placeComponents(panel);
        frame.setVisible(true);
    }
    private static void placeComponents(JPanel panel) throws Exception {
        PublicKey publicKey = getPublicKey("publicKey");
        PrivateKey privateKey = getPrivateKey("privateKey");

        panel.setLayout(null);
        JLabel userLabel = new JLabel("模式選擇:");
         // x 和 y 指定左上角的新位置，由 width 和 height 指定新的大小。
        userLabel.setBounds(10,20,80,25);
        panel.add(userLabel);

        JComboBox jComboBox = new JComboBox();
        jComboBox.addItem("請選擇");
        jComboBox.addItem("先加密再簽");
        jComboBox.addItem("先簽再加密");
        jComboBox.addItem("比較OAEP與RSA");

        // 先加密再簽的佈局 1
        JLabel ptLabel_1 = new JLabel("明文:");
        ptLabel_1.setBounds(10,50,80,25);
        ptLabel_1.setVisible(false);
        panel.add(ptLabel_1);
        JTextField ptTextField_1 = new JTextField();
        ptTextField_1.setBounds(50,50,215,25);
        ptTextField_1.setVisible(false);
        panel.add(ptTextField_1);
        JButton encryptButton_1 = new JButton("RSA-OAEP加密");
        encryptButton_1.setBounds(10, 80, 255, 25);
        encryptButton_1.setVisible(false);
        panel.add(encryptButton_1);
        JLabel ctLabel_1 = new JLabel("密文:");
        ctLabel_1.setBounds(10,110,80,25);
        ctLabel_1.setVisible(false);
        panel.add(ctLabel_1);
        JTextField ct_1 = new JTextField();
        ct_1.setBounds(50,110,215,25);
        ct_1.setVisible(false);
        panel.add(ct_1);
        JButton signButton_1 = new JButton("RSA-PSS簽章");
        signButton_1.setBounds(10, 140, 255, 25);
        signButton_1.setVisible(false);
        panel.add(signButton_1);
        JLabel signatureLabel_1 = new JLabel("簽章:");
        signatureLabel_1.setBounds(10,170,80,25);
        signatureLabel_1.setVisible(false);
        panel.add(signatureLabel_1);
        JTextField signature_1 = new JTextField();
        signature_1.setBounds(50,170,215,25);
        signature_1.setVisible(false);
        panel.add(signature_1);
        JButton verifyButton_1 = new JButton("驗證簽章");
        verifyButton_1.setBounds(10, 200, 255, 25);
        verifyButton_1.setVisible(false);
        panel.add(verifyButton_1);
        JLabel verifyLabel_1 = new JLabel("驗證結果:");
        verifyLabel_1.setBounds(10,230,80,25);
        verifyLabel_1.setVisible(false);
        panel.add(verifyLabel_1);
        JLabel verify_1 = new JLabel();
        verify_1.setBounds(70,230,215,25);
        verify_1.setVisible(false);
        panel.add(verify_1);
        JButton decryptButton_1 = new JButton("RSA-OAEP解密");
        decryptButton_1.setBounds(10, 260, 255, 25);
        decryptButton_1.setVisible(false);
        panel.add(decryptButton_1);
        JLabel decryptLabel_1 = new JLabel("明文:");
        decryptLabel_1.setBounds(10,290,80,25);
        decryptLabel_1.setVisible(false);
        panel.add(decryptLabel_1);
        JLabel decrypted_pt_1 = new JLabel();
        decrypted_pt_1.setBounds(50,290,215,25);
        decrypted_pt_1.setVisible(false);
        panel.add(decrypted_pt_1);

        // 先簽再加密的佈局 2
        JLabel ptLabel_2 = new JLabel("明文:");
        ptLabel_2.setBounds(10,50,80,25);
        ptLabel_2.setVisible(false);
        panel.add(ptLabel_2);
        JTextField ptTextField_2 = new JTextField();
        ptTextField_2.setBounds(50,50,215,25);
        ptTextField_2.setVisible(false);
        panel.add(ptTextField_2);
        JButton signButton_2 = new JButton("RSA-PSS簽章");
        signButton_2.setBounds(10, 80, 255, 25);
        signButton_2.setVisible(false);
        panel.add(signButton_2);
        JLabel signatureLabel_2 = new JLabel("簽章:");
        signatureLabel_2.setBounds(10,110,80,25);
        signatureLabel_2.setVisible(false);
        panel.add(signatureLabel_2);
        JTextField signature_2 = new JTextField();
        signature_2.setBounds(50,110,215,25);
        signature_2.setVisible(false);
        panel.add(signature_2);
        JButton encryptButton_2 = new JButton("RSA-OAEP加密");
        encryptButton_2.setBounds(10, 140, 255, 25);
        encryptButton_2.setVisible(false);
        panel.add(encryptButton_2);
        JLabel ctLabel_2 = new JLabel("密文:");
        ctLabel_2.setBounds(10,170,80,25);
        ctLabel_2.setVisible(false);
        panel.add(ctLabel_2);
        JTextField ct_2 = new JTextField();
        ct_2.setBounds(50,170,215,25);
        ct_2.setVisible(false);
        panel.add(ct_2);

        JButton decryptButton_2 = new JButton("RSA-OAEP解密");
        decryptButton_2.setBounds(10, 200, 255, 25);
        decryptButton_2.setVisible(false);
        panel.add(decryptButton_2);
        JLabel decryptLabel_2 = new JLabel("明文:");
        decryptLabel_2.setBounds(10,230,80,25);
        decryptLabel_2.setVisible(false);
        panel.add(decryptLabel_2);
        JLabel decrypted_pt_2 = new JLabel();
        decrypted_pt_2.setBounds(50,230,215,25);
        decrypted_pt_2.setVisible(false);
        panel.add(decrypted_pt_2);

        JButton verifyButton_2 = new JButton("驗證簽章");
        verifyButton_2.setBounds(10, 260, 255, 25);
        verifyButton_2.setVisible(false);
        panel.add(verifyButton_2);
        JLabel verifyLabel_2 = new JLabel("驗證結果:");
        verifyLabel_2.setBounds(10,290,80,25);
        verifyLabel_2.setVisible(false);
        panel.add(verifyLabel_2);
        JLabel verify_2 = new JLabel();
        verify_2.setBounds(70,290,215,25);
        verify_2.setVisible(false);
        panel.add(verify_2);


        jComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String Selection = (String) jComboBox.getSelectedItem();//get the selected item

                switch (Selection) {
                    case "請選擇":
                        System.out.println("用戶尚未選擇");
                        break;
                    case "先加密再簽":
                        ptLabel_1.setVisible(true);
                        ptTextField_1.setVisible(true);
                        encryptButton_1.setVisible(true);
                        ctLabel_1.setVisible(true);
                        ct_1.setVisible(true);
                        signButton_1.setVisible(true);
                        signatureLabel_1.setVisible(true);
                        signature_1.setVisible(true);
                        verifyButton_1.setVisible(true);
                        verifyLabel_1.setVisible(true);
                        verify_1.setVisible(true);
                        decryptButton_1.setVisible(true);
                        decryptLabel_1.setVisible(true);
                        decrypted_pt_1.setVisible(true);
                        ptLabel_1.setVisible(true);
                        break;
                    case "先簽再加密":
                        ptLabel_1.setVisible(false);
                        ptTextField_1.setVisible(false);
                        encryptButton_1.setVisible(false);
                        ctLabel_1.setVisible(false);
                        ct_1.setVisible(false);
                        signButton_1.setVisible(false);
                        signatureLabel_1.setVisible(false);
                        signature_1.setVisible(false);
                        verifyButton_1.setVisible(false);
                        verifyLabel_1.setVisible(false);
                        verify_1.setVisible(false);
                        decryptButton_1.setVisible(false);
                        decryptLabel_1.setVisible(false);
                        decrypted_pt_1.setVisible(false);
                        ptLabel_1.setVisible(false);

                        ptLabel_2.setVisible(true);
                        ptTextField_2.setVisible(true);
                        encryptButton_2.setVisible(true);
                        ctLabel_2.setVisible(true);
                        ct_2.setVisible(true);
                        signButton_2.setVisible(true);
                        signatureLabel_2.setVisible(true);
                        signature_2.setVisible(true);
                        verifyButton_2.setVisible(true);
                        verifyLabel_2.setVisible(true);
                        verify_2.setVisible(true);
                        decryptButton_2.setVisible(true);
                        decryptLabel_2.setVisible(true);
                        decrypted_pt_2.setVisible(true);
                        break;
                    case "比較OAEP與RSA":
                        break;
                }
            }
        });
        jComboBox.setBounds(100,20,165,25);
        panel.add(jComboBox);

        encryptButton_1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String pt = ptTextField_1.getText();
                try {
                    byte[] cipherText = RSA_OAEP_Encrypt_String(pt, publicKey);
                    ct_1.setText(bytesToHex(cipherText));
                } catch (IllegalBlockSizeException ex) {
                    throw new RuntimeException(ex);
                } catch (BadPaddingException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchPaddingException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });

        signButton_1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    byte[] cipherText = hexStringToByteArray(ct_1.getText());
                    byte[] signature_value = RSA_PSS_Sign_Byte(cipherText, privateKey);
                    signature_1.setText(bytesToHex(signature_value));
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (SignatureException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        verifyButton_1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    byte[] cipherText = hexStringToByteArray(ct_1.getText());
                    byte[] signature_value = hexStringToByteArray(signature_1.getText());
                    if (RSA_PSS_Verify_Byte(signature_value, cipherText, publicKey)){
                        verify_1.setText("驗證成功!!");
                    } else{
                        verify_1.setText("驗證失敗");
                    }
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                } catch (SignatureException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        decryptButton_1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                byte[] cipherText = hexStringToByteArray(ct_1.getText());
                try {
                    decrypted_pt_1.setText(RSA_OAEP_Decrypt_Byte(cipherText, privateKey));
                } catch (NoSuchPaddingException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (InvalidAlgorithmParameterException ex) {
                    throw new RuntimeException(ex);
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                } catch (IllegalBlockSizeException ex) {
                    throw new RuntimeException(ex);
                } catch (BadPaddingException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        signButton_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String pt = ptTextField_2.getText();
                byte[] signature_value = new byte[0];
                try {
                    signature_value = RSA_PSS_Sign_String(pt, privateKey);
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (SignatureException ex) {
                    throw new RuntimeException(ex);
                }
                signature_2.setText(bytesToHex(signature_value));
            }
        });
        encryptButton_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                byte[] signature_value = hexStringToByteArray(signature_2.getText());
                byte[] cipherText;
                try {
                    cipherText = RSA_OAEP_Encrypt_SignFirst(signature_value, publicKey);
                    ct_2.setText(bytesToHex(cipherText));
                } catch (IllegalBlockSizeException ex) {
                    throw new RuntimeException(ex);
                } catch (BadPaddingException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchPaddingException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });

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
        cipherText = RSA_OAEP_Encrypt_String("盧柏諭、RBYN圻、林君諺、李昱佑", publicKey);
        System.out.println(bytesToHex(cipherText));
        System.out.println(RSA_OAEP_Decrypt_Byte(cipherText, privateKey));

        cipherText = RSA_Encrypt("盧柏諭、RBYN圻、林君諺、李昱佑", publicKey);
        System.out.println(bytesToHex(cipherText));
        System.out.println(RSA_Decrypt(cipherText, privateKey));


        byte[] signature = RSA_PSS_Sign_String("盧柏諭、RBYN圻、林君諺、李昱佑", privateKey);
        System.out.println(bytesToHex(signature));
        System.out.println(RSA_PSS_Verify_String(signature, "盧柏諭、RBYN圻、林君諺、李昱佑", publicKey));

        cipherText = RSA_OAEP_Encrypt_SignFirst(signature, publicKey);

        System.out.println(bytesToHex(RSA_OAEP_Decrypt_SignFirst(cipherText,privateKey)));


        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    createAndShowGUI();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }
}
