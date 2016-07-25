package cn.com.zenmaster.symmetric;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by TianYu on 2016/5/29.
 * 3DES对称加密
 */
public class DesedeUtil extends EncryptUtil{

    private static DesedeUtil instance;

    public static DesedeUtil getInstance() {
        return new DesedeUtil();
    }

    /**
     *  生成 SecretKey
     *
     * @return
     */
    public byte[] getSecretKey() {
        SecretKey secretKey = null;
        try {
            //1. 秘钥生成器
            KeyGenerator keyGenerator = KeyGenerator.getInstance(SymmetricAlgorithm.DES3);
            //2. 秘钥生成器初始化 可指定秘钥长度 112 或168 默认168,x相比DES的秘钥长度更长，安全性更高
            keyGenerator.init(168);
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
    public byte[] encryptData(byte[] key, byte[] data) {
        byte[] bytes = null;
        try {
            //1. 恢复秘钥
            SecretKey secretKey = new SecretKeySpec(key, SymmetricAlgorithm.DES3);
            //2. Cipher 完成加密工作
            Cipher cipher = Cipher.getInstance(SymmetricAlgorithm.DES3);
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
    public byte[] descryptData(byte[] key, byte[] data) {
        byte[] bytes = null;
        try {
            //1. 恢复秘钥
            SecretKey secretKey = new SecretKeySpec(key, SymmetricAlgorithm.DES3);
            //2. Cipher 完成解密工作
            Cipher cipher = Cipher.getInstance(SymmetricAlgorithm.DES3);
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
