package cn.com.zenmaster;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by TianYu on 2016/5/29.
 */
public class DesUtil {

    /**
     *  生成DES SecretKey
     *
     * @return
     */
    public static byte[] getDesSecretKey() {
        SecretKey secretKey = null;
        try {
            //1. 秘钥生成器
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            //2. 秘钥生成器初始化
            keyGenerator.init(56);
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
            SecretKey secretKey = new SecretKeySpec(key, "DES");
            //2. Cipher 完成加密工作
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
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
            SecretKey secretKey = new SecretKeySpec(key, "DES");
            //2. Cipher 完成解密工作
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
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
