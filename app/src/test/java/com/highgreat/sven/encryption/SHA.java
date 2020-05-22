package com.highgreat.sven.encryption;

import org.apache.commons.codec.digest.Sha2Crypt;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class SHA {

    @Test
    public void test() throws NoSuchAlgorithmException {
        String result= Sha2Crypt.sha256Crypt("sven".getBytes());
        System.out.println(result);
    }
}
