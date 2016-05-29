package cn.com.zenmaster;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by TianYu on 2016/5/29.
 * AES对称加密
 */
public class AesUtil {

    /**
     *  生成 SecretKey
     *
     * @return
     */
    public static byte[] getSecretKey() {
        SecretKey secretKey = null;
        try {
            //1. 秘钥生成器
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            //2. 秘钥生成器初始化 可指定秘钥长度 128,从Oracle官网获得无政策权限后可为192或156长度
            keyGenerator.init(128);
            //3. 生成秘钥
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return secretKey.getEncoded();
    }

    /** 加密
     *
     * @param key
     * @param data
     * @return
     */
    public static byte[] encryptData(byte[] key, byte[] data) {
        byte[] bytes = null;
        try {
            //1. 恢复秘钥
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            //2. Cipher 完成加密工作
            Cipher cipher = Cipher.getInstance("AES");
            //3. 根据秘钥对cipher进行初始化
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            //4. 加密
            bytes =  cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    /** 解密
     *
     * @param key
     * @param data
     * @return
     */
    public static byte[] descryptData(byte[] key, byte[] data) {
        byte[] bytes = null;
        try {
            //1. 恢复秘钥
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            //2. Cipher 完成解密工作
            Cipher cipher = Cipher.getInstance("AES");
            //3. 根据秘钥对cipher进行初始化
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            //4. 解密
            bytes =  cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytes;
    }

}
