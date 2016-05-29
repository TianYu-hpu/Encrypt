package cn.com.zenmaster.asymmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by TianYu on 2016/5/29.
 */
public class RSAUtil {

    private static final String PUBLIC_KEY = "PULIC_KEY";
    private static final String PRIVATE_KEY = "PRIVATE_KEY";

    public static Map<String, Object> initKey() {
        Map<String, Object> map = null;
        try {
            //创建密钥对生成器
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA");
            //生生密钥对
            KeyPair keyPair = pairGenerator.generateKeyPair();
            //生成公钥和私钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            map = new HashMap<>();
            map.put(PUBLIC_KEY, publicKey);
            map.put(PRIVATE_KEY, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return map;
    }


    /**
     * 获取公钥
     *
     * @param map
     * @return
     */
    public static RSAPublicKey getPublicKey(Map<String, Object> map) {
        return ((RSAPublicKey)map.get(PUBLIC_KEY));
    }

    /**
     * 获取私钥
     *
     * @param map
     * @return
     */
    public static RSAPrivateKey getPrivateKey(Map<String, Object> map) {
        return ((RSAPrivateKey)map.get(PRIVATE_KEY));
    }

    /** 加密
     *
     * @param data
     * @return
     */
    public static byte[] encryptData(RSAPublicKey publicKey, byte[] data) {
        byte[] bytes = null;
        try {
            //2. Cipher 完成加密工作
            Cipher cipher = Cipher.getInstance("RSA");
            //3. 根据秘钥对cipher进行初始化
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //4. 加密
            bytes =  cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    /** 解密
     *
     * @param data
     * @return
     */
    public static byte[] descryptData(RSAPrivateKey privateKey, byte[] data) {
        byte[] bytes = null;
        try {
            //2. Cipher 完成解密工作
            Cipher cipher = Cipher.getInstance("RSA");
            //3. 根据秘钥对cipher进行初始化
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //4. 解密
            bytes =  cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytes;
    }

}
