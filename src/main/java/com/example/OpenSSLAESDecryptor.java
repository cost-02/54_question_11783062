package com.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class OpenSSLAESDecryptor {

    public static void main(String[] args) throws Exception {
        String password = "mypass"; // La tua password
        String inFile = "password.txt.enc"; // File cifrato
        String outFile = "password.txt.new"; // File decifrato

        FileInputStream fis = new FileInputStream(inFile);
        FileOutputStream fos = new FileOutputStream(outFile);

        // Leggi il sale, dovrebbe essere agli 8 byte dopo "Salted__"
        byte[] salt = new byte[8];
        fis.skip("Salted__".getBytes().length);
        fis.read(salt);

        // Deriva la chiave e l'IV usando MD5 (metodo compatibile con OpenSSL)
        byte[] keyAndIV = EVP_BytesToKey(32, 16, 1, salt, password.getBytes(), "MD5");
        byte[] keyValue = Arrays.copyOfRange(keyAndIV, 0, 32);
        byte[] ivValue = Arrays.copyOfRange(keyAndIV, 32, 48);

        // Imposta la chiave e l'IV per la decifratura
        SecretKeySpec key = new SecretKeySpec(keyValue, "AES");
        AlgorithmParameterSpec iv = new IvParameterSpec(ivValue);

        // Inizializza il Cipher per AES-256-CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        // Leggi i dati cifrati e decifrati
        byte[] input = new byte[4096];
        int bytesRead;
        while ((bytesRead = fis.read(input)) != -1) {
            byte[] output = cipher.update(input, 0, bytesRead);
            if (output != null) {
                fos.write(output);
            }
        }

        byte[] output = cipher.doFinal();
        if (output != null) {
            fos.write(output);
        }

        fis.close();
        fos.flush();
        fos.close();
    }

    // Funzione di derivazione della chiave compatibile con OpenSSL
    public static byte[] EVP_BytesToKey(int keyLen, int ivLen, int mdCount, byte[] salt, byte[] password, String mdName) throws Exception {
        MessageDigest md = MessageDigest.getInstance(mdName);
        byte[] keyAndIV = new byte[keyLen + ivLen];
        byte[] currentMD = null;
        int generatedLength = 0;
        while (generatedLength < keyLen + ivLen) {
            md.update(currentMD != null ? currentMD : new byte[0]);
            md.update(password);
            md.update(salt);
            currentMD = md.digest();

            for (int i = 1; i < mdCount; i++) {
                currentMD = md.digest(currentMD);
            }

            int copyLength = Math.min(currentMD.length, keyLen + ivLen - generatedLength);
            System.arraycopy(currentMD, 0, keyAndIV, generatedLength, copyLength);
            generatedLength += copyLength;
        }
        return keyAndIV;
    }
}
