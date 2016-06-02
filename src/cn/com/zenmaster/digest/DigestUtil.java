package cn.com.zenmaster.digest;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by TianYu on 2016/5/29.
 */
public class DigestUtil {


    /**
     * 生成 MD5或SHA算法的摘要摘要
     *
     * @param data
     * @return
     */
    public static byte[] getDigest(byte[] data, String digestAlgorithm) {
        byte[] result = null;
        try {
            // 初始化
            MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
            // 生成摘要
            result = digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }



    /** 获取hmac  secretkey
     *
     * @return
     */
    public static byte[] getHMACSecretKey(String digestAlgorithm) {
        byte[] result = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(digestAlgorithm);
            SecretKey secretKey = keyGenerator.generateKey();
            result = secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }


    /** 获取hmac 摘要
     *
     * @return
     */
    public static byte[] getHMACDigest(byte[] key, byte[] data, String digestAlgorithm) {
        byte[] result = null;
        try {
            //从字节数组还原秘钥
            SecretKey secretKey = new SecretKeySpec(key, digestAlgorithm);
            //实例化Mac
            Mac mac = Mac.getInstance(DigestAlgorithm.HmacMD5);
            //用秘钥初始化mac
            mac.init(secretKey);
            //执行消息摘要
            result = mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return result;
    }

}
