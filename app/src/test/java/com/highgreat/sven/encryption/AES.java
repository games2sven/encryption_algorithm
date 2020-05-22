package com.highgreat.sven.encryption;

import org.junit.Test;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES {

    public static String ALGORITHM="AES";

    @Test
    public void test() throws Exception{
        String content = "svendafsdfasdfasdfasdfasdfasdfas2598237532985723498573248";
        String password="1232351325123";
        //加密
        byte[] encrypt = encrypt(content, password);
        System.out.println("加密后的数据:"+new String(encrypt));
        //解密
        byte[] decrypt = decrypt(encrypt, password);
        System.out.println("解密后的内容:"+new String(decrypt));
    }

    public static byte[] encrypt(String content,String password) throws Exception{
        //创建AES的key生产者
        KeyGenerator kgen=KeyGenerator.getInstance(ALGORITHM);
        //利用用户密码作为随机数初始化
        kgen.init(128,new SecureRandom(password.getBytes()));
        //根据用户密码，生成一个密钥  (所有对称算法通用的)
        SecretKey secretKey=kgen.generateKey();

        //对秘钥进行基本的编码
        byte[] keyEncoded = secretKey.getEncoded();
        //转换成AES专用的密钥 RoundKey
        SecretKeySpec key = new SecretKeySpec(keyEncoded,ALGORITHM);
        //创建一个密码器
        Cipher cipher= Cipher.getInstance(ALGORITHM);
        //开始加密
        byte[] byteContent=content.getBytes();
        //初始化为加密模式
        cipher.init(Cipher.ENCRYPT_MODE,key);
        //加密
        byte[] result = cipher.doFinal(byteContent);
        //如果数据很多，就用 cipher.update(),最后才用cipher.doFinal()
        return result;
    }

    public static byte[] decrypt(byte[] content,String password) throws Exception{
        //创建AES的key生产者
        KeyGenerator kgen=KeyGenerator.getInstance(ALGORITHM);
        //利用用户密码作为随机数初始化
        kgen.init(128,new SecureRandom(password.getBytes()));
        //根据用户密码，生成一个密钥  (所有对称算法通用的)
        SecretKey secretKey=kgen.generateKey();
        //对密钥进行基本的编码
        byte[] enCodeFormat=secretKey.getEncoded();
        //转换成AES专用的密钥 RoundKey
        SecretKeySpec key=new SecretKeySpec(enCodeFormat,ALGORITHM);
        //创建一个密码器
        Cipher cipher=Cipher.getInstance(ALGORITHM);
        //解密
        cipher.init(Cipher.DECRYPT_MODE,key);
        byte[] result=cipher.doFinal(content);
        return result;
    }
}
