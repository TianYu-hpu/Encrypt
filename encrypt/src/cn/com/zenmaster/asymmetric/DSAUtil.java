package cn.com.zenmaster.asymmetric;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import cn.com.zenmaster.KeyUtil;

/**
 * Created by TianYu on 2016/5/29.
 */
public class DSAUtil extends KeyUtil {

    public static Map<String, Object> initKey() {
        Map<String, Object> map = null;
        try {
            //创建密钥对生成器
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance(AsymmetricAlgorithm.DSA);
            //生生密钥对
            KeyPair keyPair = pairGenerator.generateKeyPair();
            //生成公钥和私钥
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            map = new HashMap<>();
            map.put(PUBLIC_KEY, publicKey);
            map.put(PRIVATE_KEY, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return map;
    }


    /** 加密
     *
     * @param data
     * @return
     */
    public static byte[] encryptData(DSAPublicKey publicKey, byte[] data) {
        byte[] bytes = null;
        try {
            //2. Cipher 完成加密工作
            Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm.DSA);
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
    public static byte[] descryptData(DSAPrivateKey privateKey, byte[] data) {
        byte[] bytes = null;
        try {
            //2. Cipher 完成解密工作
            Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm.DSA);
            //3. 根据秘钥对cipher进行初始化
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //4. 解密
            bytes =  cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    /**
     * 获取公钥
     *
     * @param publicKey
     * @return
     */
    @SuppressWarnings("Duplicates")
    @Override
    public PublicKey  getPublicKey(byte[] publicKey) {
        PublicKey rsaPublicKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.DSA);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            rsaPublicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return rsaPublicKey;
    }

    /**
     * 获取私钥
     *
     * @param privateKey
     *
     * @return
     */
    @SuppressWarnings("Duplicates")
    @Override
    public PrivateKey getPrivateKey(byte[] privateKey) {
        PrivateKey rsaPrivateKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.DSA);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            rsaPrivateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return rsaPrivateKey;
    }

}
