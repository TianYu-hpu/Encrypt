package cn.com.zenmaster.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import cn.com.zenmaster.KeyUtil;
import cn.com.zenmaster.symmetric.SymmetricAlgorithm;

/**
 * Created by TianYu on 2016/5/29.
 */
public class DHUtils extends KeyUtil {

    private static final String PUBLIC_KEY = "PULIC_KEY";
    private static final String PRIVATE_KEY = "PRIVATE_KEY";

    /**
     * 甲方初始化生成秘钥对
     *
     */
    public static Map<String, Object> initKey() {
        //创建密钥对生成器
        KeyPairGenerator pairGenerator = null;
        try {
            pairGenerator = KeyPairGenerator.getInstance(AsymmetricAlgorithm.DH);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //初始化密钥对生成器 默认是1024，可以是512-1024之间的64的整数倍
        pairGenerator.initialize(1024);
        //生成秘钥对
        KeyPair keyPair = pairGenerator.generateKeyPair();
        //生成公钥
        PublicKey publicKey = keyPair.getPublic();
        //生成私钥
        PrivateKey privateKey = keyPair.getPrivate();
        HashMap<String, Object> map = new HashMap<>();
        map.put(PUBLIC_KEY, publicKey);
        map.put(PRIVATE_KEY, privateKey);
        return map;
    }

    /**
     * 乙方根据甲方的公钥产生秘钥对
     *
     * @param key
     * @return
     */
    public static Map<String, Object> initKey(byte[] key) {
        HashMap<String, Object> map = null;
        try {
            //将甲方的字节数组公钥通过X509转化为PublicKey
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            //实例化秘钥工厂
            KeyFactory factory = KeyFactory.getInstance(AsymmetricAlgorithm.DH);
            //产生甲方的公钥
            DHPublicKey dhPublicKey = (DHPublicKey) factory.generatePublic(keySpec);
            //剖析甲方公钥，得到其参数
            DHParameterSpec parameterSpec = dhPublicKey.getParams();
            //创建秘钥对生成器
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AsymmetricAlgorithm.DH);
            //初始化密钥对生成器
            keyPairGenerator.initialize(parameterSpec);
            //产生秘钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //获取公钥
            PublicKey publicKey1 = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            map = new HashMap<>();
            map.put(PUBLIC_KEY, publicKey1);
            map.put(PRIVATE_KEY, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return map;
    }

    /**
     * 根据对方的公钥和自己的私钥产生本地秘钥
     *
     * @param publicKey
     * @param privateKey
     */
    public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) {
        byte[] result = null;
        try {
            //实例化秘钥工厂
            KeyFactory factory = KeyFactory.getInstance(AsymmetricAlgorithm.DH);
            //将公钥从字节数组转换为PublicKey
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
            PublicKey pubKey = factory.generatePublic(pubKeySpec);
            //将私钥从字节数组转换为PrivateKey
            PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKey);
            PrivateKey priKey = factory.generatePrivate(priKeySpec);

            //将公钥和私钥从字节数组转换为PrivateKey和PublicKey
            //实例化KeyAgreement
            KeyAgreement keyAgreement = KeyAgreement.getInstance(AsymmetricAlgorithm.DH);
            //用自己的私钥初始哈keyAgreement
            keyAgreement.init(priKey);
            //结合对方的公钥进行计算
            keyAgreement.doPhase(pubKey, true);
            //开始生成本地秘钥
            SecretKey secretKey = keyAgreement.generateSecret(SymmetricAlgorithm.AES);
            result = secretKey.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return result;
    }

	/** 获取PublicKey形式的公钥
     * 
     * @param publicKey
     * @return
     */
    @Override
    public PublicKey getPublicKey(byte[] publicKey) {
        PublicKey pubKey = null;
        try {
            //实例化秘钥工厂
            KeyFactory factory = KeyFactory.getInstance(AsymmetricAlgorithm.DH);
            //将公钥从字节数组转换为PublicKey
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
            pubKey = factory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return pubKey;
    }

	/** 获取PrivateKey形式的私钥
     *
     * @param privateKey
     * @return
     */
    @Override
    public PrivateKey getPrivateKey(byte[] privateKey) {
        PrivateKey priKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.DH);
            PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(privateKey);
            priKey = keyFactory.generatePrivate(priKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return priKey;
    }
}
