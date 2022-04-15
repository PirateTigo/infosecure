package ru.sibsutis.security.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GostDigest {

    ByteArrayInputStream digest(ByteArrayInputStream messageStream) {
        ByteArrayOutputStream signedMessage = new ByteArrayOutputStream();
        try {
            int data = messageStream.read();

            while (data != -1) {
                signedMessage.write(data);
                data = messageStream.read();
            }

            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            byte[] bytes = signedMessage.toByteArray();
            byte[] hash = messageDigest.digest(bytes);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
