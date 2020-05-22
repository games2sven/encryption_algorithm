package com.highgreat.sven.encryption;

import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSA {

    public static String ALGORITHM = "RSA";
    //指定key的位数
    public static int KEYSIZE = 1024;//65536
    //指定公钥的存放文件
    public static String PUBLIC_KEY_FILE = "public_key.dat";
    //指定私钥的存放文件
    public static String PRIVATE_KEY_FILE = "private_key.dat";

    @Test
    public void test() throws Exception{
        //客户端用公钥加密
        String content = "sven";
        String encrypt = encrypt(content);
        System.out.println("密文："+encrypt);
        //到了服务器后，用私钥解密
        String target = decrypt(encrypt);
        System.out.println("明文："+target);
    }

    /**
     * 生成秘钥对 公  私
     *
     * @throws Exception
     */
    public static void generateKeyPair() throws Exception {
        SecureRandom sr = new SecureRandom();
        //需要一个KeyPairGenerator对象
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEYSIZE, sr);
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //得到公钥
        PublicKey keyPublic = keyPair.getPublic();
        //得到私钥
        PrivateKey keyPrivate = keyPair.getPrivate();

        //可以写入文件后，这两个文件分别放到服务器和客户端
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
        ObjectOutputStream objectOutputStream1 = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE));
        objectOutputStream.writeObject(keyPublic);
        objectOutputStream1.writeObject(keyPrivate);
        objectOutputStream.close();
        objectOutputStream1.close();
    }

    /**
     * 加密
     */
    public static String encrypt(String source) throws Exception {
        generateKeyPair();
        //取出公钥
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        Key key = (Key) ois.readObject();
        ois.close();
        //开始用公钥
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = source.getBytes();
        byte[] aFinal = cipher.doFinal(bytes);
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(aFinal);
    }

    /**
     * 解密
     * @param cryptText
     * @return
     * @throws Exception
     */
    public static String decrypt(String cryptText) throws Exception {
        //读文件，取到私钥
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        Key key = (Key) ois.readObject();
        ois.close();
        //解密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decode = decoder.decode(cryptText);
        byte[] bytes = cipher.doFinal(decode);
        return new String(bytes);
    }
}