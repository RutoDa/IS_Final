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
        // 生成sender的key pair
        KeyPairGenerator generator1 = KeyPairGenerator.getInstance("RSA");
        generator1.initialize(1024);
        KeyPair pair1 = generator1.generateKeyPair();
        PrivateKey senderPrivateKey = pair1.getPrivate();
        PublicKey senderPublicKey = pair1.getPublic();
        // 將 sender public key 保存在文件中
        try (FileOutputStream fos = new FileOutputStream("senderPublicKey")) {
            fos.write(senderPublicKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 將 sender private key 保存在文件中
        try (FileOutputStream fos = new FileOutputStream("senderPrivateKey")) {
            fos.write(senderPrivateKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 生成receiver的ker pair
        KeyPairGenerator generator2 = KeyPairGenerator.getInstance("RSA");
        generator2.initialize(1024);
        KeyPair  pair2 = generator2.generateKeyPair();
        PrivateKey receiverPrivateKey = pair2.getPrivate();
        PublicKey receiverPublicKey = pair2.getPublic();
        // 將 receiver public key 保存在文件中
        try (FileOutputStream fos = new FileOutputStream("receiverPublicKey")) {
            fos.write(receiverPublicKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 將 receiver private key 保存在文件中
        try (FileOutputStream fos = new FileOutputStream("receiverPrivateKey")) {
            fos.write(receiverPrivateKey.getEncoded());
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
        JFrame frame = new JFrame("資安期末報告-第二組-RSA-OAEP與RSA-PSS");
        // Setting the width and height of frame
        frame.setSize(600, 800);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JPanel panel = new JPanel();
        // 添加面板
        frame.add(panel);
        placeComponents(panel);
        frame.setVisible(true);
    }
    private static void placeComponents(JPanel panel) throws Exception {
        final PublicKey[] receiverPublicKey = {getPublicKey("receiverPublicKey")};
        final PrivateKey[] receiverPrivateKey = {getPrivateKey("receiverPrivateKey")};
        final PublicKey[] senderPublicKey = {getPublicKey("senderPublicKey")};
        final PrivateKey[] senderPrivateKey = {getPrivateKey("senderPrivateKey")};

        JButton newKey = new JButton("產生新的一組鑰匙");
        newKey.setBounds(10, 20, 580, 25);
        panel.add(newKey);

        panel.setLayout(null);
        JLabel senderPubLabel = new JLabel("傳送者公鑰:");
        senderPubLabel.setBounds(10,50,80,25);
        panel.add(senderPubLabel);
        JLabel senderPub = new JLabel(bytesToHex(senderPublicKey[0].getEncoded()));
        senderPub.setBounds(90,50,500,25);
        panel.add(senderPub);

        JLabel senderPriLabel = new JLabel("傳送者私鑰:");
        senderPriLabel.setBounds(10,80,80,25);
        panel.add(senderPriLabel);
        JLabel senderPri = new JLabel(bytesToHex(senderPrivateKey[0].getEncoded()));
        senderPri.setBounds(90,80,500,25);
        panel.add(senderPri);

        JLabel receiverPubLabel = new JLabel("接收者公鑰:");
        receiverPubLabel.setBounds(10,110,80,25);
        panel.add(receiverPubLabel);
        JLabel receiverPub = new JLabel(bytesToHex(receiverPublicKey[0].getEncoded()));
        receiverPub.setBounds(90,110,500,25);
        panel.add(receiverPub);

        JLabel receiverPriLabel = new JLabel("接收者私鑰:");
        receiverPriLabel.setBounds(10,140,80,25);
        panel.add(receiverPriLabel);
        JLabel receiverPri = new JLabel(bytesToHex(receiverPrivateKey[0].getEncoded()));
        receiverPri.setBounds(90,140,500,25);
        panel.add(receiverPri);



        JLabel userLabel = new JLabel("模式選擇:");
         // x 和 y 指定左上角的新位置，由 width 和 height 指定新的大小。
        userLabel.setBounds(10,170,80,25);
        panel.add(userLabel);

        JComboBox jComboBox = new JComboBox();
        jComboBox.addItem("請選擇");
        jComboBox.addItem("先加密再簽");
        jComboBox.addItem("先簽再加密");
        jComboBox.addItem("比較OAEP與RSA的密文");

        // 先加密再簽的佈局 1
        JLabel ptLabel_1 = new JLabel("訊息:");
        ptLabel_1.setBounds(10,200,80,25);
        ptLabel_1.setVisible(false);
        panel.add(ptLabel_1);
        JTextField ptTextField_1 = new JTextField();
        ptTextField_1.setBounds(50,200,540,25);
        ptTextField_1.setVisible(false);
        panel.add(ptTextField_1);
        JButton encryptButton_1 = new JButton("RSA-OAEP加密");
        encryptButton_1.setBounds(10, 230, 580, 25);
        encryptButton_1.setVisible(false);
        panel.add(encryptButton_1);
        JLabel ctLabel_1 = new JLabel("密文:");
        ctLabel_1.setBounds(10,260,80,25);
        ctLabel_1.setVisible(false);
        panel.add(ctLabel_1);
        JTextField ct_1 = new JTextField();
        ct_1.setBounds(50,260,540,25);
        ct_1.setVisible(false);
        panel.add(ct_1);
        JButton signButton_1 = new JButton("RSA-PSS簽章");
        signButton_1.setBounds(10, 290, 580, 25);
        signButton_1.setVisible(false);
        panel.add(signButton_1);
        JLabel signatureLabel_1 = new JLabel("簽章:");
        signatureLabel_1.setBounds(10,320,80,25);
        signatureLabel_1.setVisible(false);
        panel.add(signatureLabel_1);
        JTextField signature_1 = new JTextField();
        signature_1.setBounds(50,320,540,25);
        signature_1.setVisible(false);
        panel.add(signature_1);
        JButton verifyButton_1 = new JButton("驗證簽章");
        verifyButton_1.setBounds(10, 350, 580, 25);
        verifyButton_1.setVisible(false);
        panel.add(verifyButton_1);
        JLabel verifyLabel_1 = new JLabel("驗證結果:");
        verifyLabel_1.setBounds(10,380,80,25);
        verifyLabel_1.setVisible(false);
        panel.add(verifyLabel_1);
        JLabel verify_1 = new JLabel();
        verify_1.setBounds(70,380,520,25);
        verify_1.setVisible(false);
        panel.add(verify_1);
        JButton decryptButton_1 = new JButton("RSA-OAEP解密");
        decryptButton_1.setBounds(10, 410, 580, 25);
        decryptButton_1.setVisible(false);
        panel.add(decryptButton_1);
        JLabel decryptLabel_1 = new JLabel("訊息:");
        decryptLabel_1.setBounds(10,440,80,25);
        decryptLabel_1.setVisible(false);
        panel.add(decryptLabel_1);
        JLabel decrypted_pt_1 = new JLabel();
        decrypted_pt_1.setBounds(50,440,540,25);
        decrypted_pt_1.setVisible(false);
        panel.add(decrypted_pt_1);

        // 先簽再加密的佈局 2
        JLabel ptLabel_2 = new JLabel("明文:");
        ptLabel_2.setBounds(10,200,80,25);
        ptLabel_2.setVisible(false);
        panel.add(ptLabel_2);
        JTextField ptTextField_2 = new JTextField();
        ptTextField_2.setBounds(50,200,540,25);
        ptTextField_2.setVisible(false);
        panel.add(ptTextField_2);
        JButton signButton_2 = new JButton("RSA-PSS簽章");
        signButton_2.setBounds(10, 230, 580, 25);
        signButton_2.setVisible(false);
        panel.add(signButton_2);
        JLabel signatureLabel_2 = new JLabel("簽章:");
        signatureLabel_2.setBounds(10,260,80,25);
        signatureLabel_2.setVisible(false);
        panel.add(signatureLabel_2);
        JTextField signature_2 = new JTextField();
        signature_2.setBounds(50,260,540,25);
        signature_2.setVisible(false);
        panel.add(signature_2);
        JLabel messageLabel_2 = new JLabel("訊息:");
        messageLabel_2.setBounds(10,290,80,25);
        messageLabel_2.setVisible(false);
        panel.add(messageLabel_2);
        JTextField message_2 = new JTextField();
        message_2.setBounds(50,290,540,25);
        message_2.setVisible(false);
        panel.add(message_2);
        JButton encryptButton_2 = new JButton("RSA-OAEP加密");
        encryptButton_2.setBounds(10, 320, 580, 25);
        encryptButton_2.setVisible(false);
        panel.add(encryptButton_2);
        JLabel ctLabel_2 = new JLabel("密文:");
        ctLabel_2.setBounds(10,350,80,25);
        ctLabel_2.setVisible(false);
        panel.add(ctLabel_2);
        JTextField ct_2 = new JTextField();
        ct_2.setBounds(50,350,540,25);
        ct_2.setVisible(false);
        panel.add(ct_2);
        JButton decryptButton_2 = new JButton("RSA-OAEP解密");
        decryptButton_2.setBounds(10, 380, 580, 25);
        decryptButton_2.setVisible(false);
        panel.add(decryptButton_2);
        JLabel decryptSignLabel_2 = new JLabel("解密後簽章:");
        decryptSignLabel_2.setBounds(10,410,100,25);
        decryptSignLabel_2.setVisible(false);
        panel.add(decryptSignLabel_2);
        JLabel decryptedSign_2 = new JLabel();
        decryptedSign_2.setBounds(90,410,500,25);
        decryptedSign_2.setVisible(false);
        panel.add(decryptedSign_2);
        JLabel decryptMessageLabel_2 = new JLabel("解密後訊息:");
        decryptMessageLabel_2.setBounds(10,440,100,25);
        decryptMessageLabel_2.setVisible(false);
        panel.add(decryptMessageLabel_2);
        JLabel decryptedMessage_2 = new JLabel();
        decryptedMessage_2.setBounds(90,440,500,25);
        decryptedMessage_2.setVisible(false);
        panel.add(decryptedMessage_2);
        JButton verifyButton_2 = new JButton("驗證簽章");
        verifyButton_2.setBounds(10, 470, 580, 25);
        verifyButton_2.setVisible(false);
        panel.add(verifyButton_2);
        JLabel verifyLabel_2 = new JLabel("驗證結果:");
        verifyLabel_2.setBounds(10,500,580,25);
        verifyLabel_2.setVisible(false);
        panel.add(verifyLabel_2);
        JLabel verify_2 = new JLabel();
        verify_2.setBounds(70,500,520,25);
        verify_2.setVisible(false);
        panel.add(verify_2);

        // 比較RSA與RSA-OAEP的佈局 3
        JLabel ptLabel_3 = new JLabel("明文:");
        ptLabel_3.setBounds(10,200,80,25);
        ptLabel_3.setVisible(false);
        panel.add(ptLabel_3);
        JTextField ptTextField_3 = new JTextField();
        ptTextField_3.setBounds(50,200,540,25);
        ptTextField_3.setVisible(false);
        panel.add(ptTextField_3);
        JButton encryptButton_3 = new JButton("加密");
        encryptButton_3.setBounds(10, 230, 580, 25);
        encryptButton_3.setVisible(false);
        panel.add(encryptButton_3);
        JLabel RSAResultLabel_3 = new JLabel("RSA的密文:");
        RSAResultLabel_3.setBounds(10,260,100,25);
        RSAResultLabel_3.setVisible(false);
        panel.add(RSAResultLabel_3 );
        JLabel RSAResult_3 = new JLabel();
        RSAResult_3.setBounds(10,290,580,25);
        RSAResult_3.setVisible(false);
        panel.add(RSAResult_3);
        JLabel RSAOAEPResultLabel_3 = new JLabel("RSA-OAEP的密文:");
        RSAOAEPResultLabel_3.setBounds(10,320,150,25);
        RSAOAEPResultLabel_3.setVisible(false);
        panel.add(RSAOAEPResultLabel_3);
        JLabel RSAOAEPResult_3 = new JLabel();
        RSAOAEPResult_3.setBounds(10,350,580,25);
        RSAOAEPResult_3.setVisible(false);
        panel.add(RSAOAEPResult_3);


        jComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String Selection = (String) jComboBox.getSelectedItem();//get the selected item

                switch (Selection) {
                    case "請選擇":
                        System.out.println("用戶尚未選擇");
                        break;
                    case "先加密再簽":
                        ptLabel_3.setVisible(false);
                        ptTextField_3.setVisible(false);
                        encryptButton_3.setVisible(false);
                        RSAResultLabel_3.setVisible(false);
                        RSAResult_3.setVisible(false);
                        RSAOAEPResultLabel_3.setVisible(false);
                        RSAOAEPResult_3.setVisible(false);

                        ptLabel_2.setVisible(false);
                        ptTextField_2.setVisible(false);
                        encryptButton_2.setVisible(false);
                        ctLabel_2.setVisible(false);
                        ct_2.setVisible(false);
                        signButton_2.setVisible(false);
                        signatureLabel_2.setVisible(false);
                        signature_2.setVisible(false);
                        verifyButton_2.setVisible(false);
                        verifyLabel_2.setVisible(false);
                        verify_2.setVisible(false);
                        decryptButton_2.setVisible(false);
                        decryptSignLabel_2.setVisible(false);
                        decryptedSign_2.setVisible(false);
                        messageLabel_2.setVisible(false);
                        message_2.setVisible(false);
                        decryptedMessage_2.setVisible(false);
                        decryptMessageLabel_2.setVisible(false);

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
                        ptLabel_3.setVisible(false);
                        ptTextField_3.setVisible(false);
                        encryptButton_3.setVisible(false);
                        RSAResultLabel_3.setVisible(false);
                        RSAResult_3.setVisible(false);
                        RSAOAEPResultLabel_3.setVisible(false);
                        RSAOAEPResult_3.setVisible(false);

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
                        decryptSignLabel_2.setVisible(true);
                        decryptedSign_2.setVisible(true);
                        messageLabel_2.setVisible(true);
                        message_2.setVisible(true);
                        decryptedMessage_2.setVisible(true);
                        decryptMessageLabel_2.setVisible(true);
                        break;
                    case "比較OAEP與RSA的密文":
                        ptLabel_2.setVisible(false);
                        ptTextField_2.setVisible(false);
                        encryptButton_2.setVisible(false);
                        ctLabel_2.setVisible(false);
                        ct_2.setVisible(false);
                        signButton_2.setVisible(false);
                        signatureLabel_2.setVisible(false);
                        signature_2.setVisible(false);
                        verifyButton_2.setVisible(false);
                        verifyLabel_2.setVisible(false);
                        verify_2.setVisible(false);
                        decryptButton_2.setVisible(false);
                        decryptSignLabel_2.setVisible(false);
                        decryptedSign_2.setVisible(false);
                        messageLabel_2.setVisible(false);
                        message_2.setVisible(false);
                        decryptedMessage_2.setVisible(false);
                        decryptMessageLabel_2.setVisible(false);

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

                        ptLabel_3.setVisible(true);
                        ptTextField_3.setVisible(true);
                        encryptButton_3.setVisible(true);
                        RSAResultLabel_3.setVisible(true);
                        RSAResult_3.setVisible(true);
                        RSAOAEPResultLabel_3.setVisible(true);
                        RSAOAEPResult_3.setVisible(true);
                        break;
                }
            }
        });
        jComboBox.setBounds(100,170,200,25);
        panel.add(jComboBox);

        newKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    RSA_KEY_Generator();
                    receiverPublicKey[0] = getPublicKey("receiverPublicKey");
                    receiverPrivateKey[0] = getPrivateKey("receiverPrivateKey");
                    senderPublicKey[0] = getPublicKey("senderPublicKey");
                    senderPrivateKey[0] = getPrivateKey("senderPrivateKey");
                    senderPub.setText(bytesToHex(senderPublicKey[0].getEncoded()));
                    senderPri.setText(bytesToHex(senderPrivateKey[0].getEncoded()));
                    receiverPub.setText(bytesToHex(receiverPublicKey[0].getEncoded()));
                    receiverPri.setText(bytesToHex(receiverPrivateKey[0].getEncoded()));
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        encryptButton_1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String pt = ptTextField_1.getText();
                try {
                    byte[] cipherText = RSA_OAEP_Encrypt_String(pt, receiverPublicKey[0]);
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
                    byte[] signature_value = RSA_PSS_Sign_Byte(cipherText, senderPrivateKey[0]);
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
                    if (RSA_PSS_Verify_Byte(signature_value, cipherText, senderPublicKey[0])){
                        verify_1.setText("驗證成功!!");
                        decryptButton_1.setEnabled(true);
                    } else{
                        verify_1.setText("驗證失敗");
                        decryptButton_1.setEnabled(false);
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
                    decrypted_pt_1.setText(RSA_OAEP_Decrypt_Byte(cipherText, receiverPrivateKey[0]));
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
                    signature_value = RSA_PSS_Sign_String(pt, senderPrivateKey[0]);
                } catch (InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                } catch (SignatureException ex) {
                    throw new RuntimeException(ex);
                }
                signature_2.setText(bytesToHex(signature_value));
                message_2.setText(pt);
            }
        });
        encryptButton_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                byte[] signature_value = hexStringToByteArray(signature_2.getText());
                byte[] cipherText_sign, cipherText_message;
                String message = message_2.getText();
                try {
                    cipherText_sign = RSA_OAEP_Encrypt_SignFirst(signature_value, receiverPublicKey[0]);
                    cipherText_message = RSA_OAEP_Encrypt_String(message, receiverPublicKey[0]);
                    ct_2.setText(bytesToHex(cipherText_sign)+bytesToHex(cipherText_message));
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
        decryptButton_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                byte[] mergeCT = hexStringToByteArray(ct_2.getText());
                byte[] ct_sign = Arrays.copyOfRange(mergeCT, 0, 384);
                byte[] ct_message = Arrays.copyOfRange(mergeCT, 384, 512);
                try {
                    decryptedSign_2.setText(bytesToHex(RSA_OAEP_Decrypt_SignFirst(ct_sign, receiverPrivateKey[0])));
                    decryptedMessage_2.setText(RSA_OAEP_Decrypt_Byte(ct_message, receiverPrivateKey[0]));
                    verifyButton_2.enable(true);
                } catch (NoSuchPaddingException ex) {
                    decryptedSign_2.setText("OAEP 解碼發生錯誤");
                    decryptedMessage_2.setText("OAEP 解碼發生錯誤");
                    verifyButton_2.enable(false);
                    verify_2.setText("");
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
                    decryptedSign_2.setText("OAEP 解碼發生錯誤");
                    decryptedMessage_2.setText("OAEP 解碼發生錯誤");
                    verifyButton_2.enable(false);
                    verify_2.setText("");
                    throw new RuntimeException(ex);
                } catch (InvalidAlgorithmParameterException ex) {
                    decryptedSign_2.setText("OAEP 解碼發生錯誤");
                    decryptedMessage_2.setText("OAEP 解碼發生錯誤");
                    verifyButton_2.enable(false);
                    verify_2.setText("");
                    throw new RuntimeException(ex);
                } catch (InvalidKeyException ex) {
                    decryptedSign_2.setText("OAEP 解碼發生錯誤");
                    decryptedMessage_2.setText("OAEP 解碼發生錯誤");
                    verifyButton_2.enable(false);
                    verify_2.setText("");
                    throw new RuntimeException(ex);
                } catch (IllegalBlockSizeException ex) {
                    decryptedSign_2.setText("OAEP 解碼發生錯誤");
                    decryptedMessage_2.setText("OAEP 解碼發生錯誤");
                    verifyButton_2.enable(false);
                    verify_2.setText("");
                    throw new RuntimeException(ex);
                } catch (BadPaddingException ex) {
                    decryptedSign_2.setText("OAEP 解碼發生錯誤");
                    decryptedMessage_2.setText("OAEP 解碼發生錯誤");
                    verifyButton_2.enable(false);
                    verify_2.setText("");
                    throw new RuntimeException(ex);
                }
            }
        });
        verifyButton_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String message = decryptedMessage_2.getText();
                byte[] sign = hexStringToByteArray(decryptedSign_2.getText());
                try {
                    if (RSA_PSS_Verify_String(sign, message, senderPublicKey[0])) {
                        verify_2.setText("驗證成功!!");
                    } else {
                        verify_2.setText("驗證失敗!!");
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
        encryptButton_3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String pt = ptTextField_3.getText();
                try {
                    RSAResult_3.setText(bytesToHex(RSA_Encrypt(pt, receiverPublicKey[0])));
                    RSAOAEPResult_3.setText(bytesToHex(RSA_OAEP_Encrypt_String(pt, receiverPublicKey[0])));
                } catch (NoSuchPaddingException ex) {
                    throw new RuntimeException(ex);
                } catch (NoSuchAlgorithmException ex) {
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
    }


    public static void main(String argv[]) throws Exception {
        // add provider only if it's not in the JVM
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        RSA_KEY_Generator();
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
