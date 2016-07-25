package cn.com.zenmaster;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import cn.com.zenmaster.asymmetric.DSAUtil;
import cn.com.zenmaster.signature.DSASignature;

/**
 * Created by TianYu on 2016/5/29.
 */
public class Test {

    public static void main(String args[]) {
        String data = "jikexueyuan";

        //DES 加解密
        /*byte[] dessecretKey = DesUtil.getInstance().getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(dessecretKey));
        byte[] encryptData = DesUtil.getInstance().encryptData(dessecretKey, data.getBytes());
        System.out.println("des 加密" + BytesToHex.fromBytesToHex(encryptData));
        System.out.println("des 解密" + new String(DesUtil.getInstance().descryptData(dessecretKey, encryptData)));*/

        // 3DES 加解密
        /*byte[] desedeSecretKey = DesedeUtil.getInstance().getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(desedeSecretKey));
        byte[] encryptDataDesede = DesedeUtil.getInstance().encryptData(desedeSecretKey, data.getBytes());
        System.out.println("3des 加密" + BytesToHex.fromBytesToHex(encryptDataDesede));
        System.out.println("3des 解密" + new String(DesedeUtil.getInstance().descryptData(desedeSecretKey, encryptDataDesede)));*/

        // AES 加解密
        /*byte[] aesSecretKey = AesUtil.getInstance().getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(aesSecretKey));
        byte[] encryptDataAes = AesUtil.getInstance().encryptData(aesSecretKey, data.getBytes());
        System.out.println("aes 加密" + BytesToHex.fromBytesToHex(encryptDataAes));
        System.out.println("aes 解密" + new String(AesUtil.getInstance().descryptData(aesSecretKey, encryptDataAes)));*/

        //摘要算法
        /*System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getDigest(data.getBytes(), DigestAlgorithm.MD2)));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getDigest(data.getBytes(), DigestAlgorithm.MD5)));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getDigest(data.getBytes(), DigestAlgorithm.SHA)));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getDigest(data.getBytes(), DigestAlgorithm.SHA256)));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getDigest(data.getBytes(), DigestAlgorithm.SHA384)));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getDigest(data.getBytes(), DigestAlgorithm.SHA512)));
        byte[] secretKey = DigestUtil.getHMACSecretKey(DigestAlgorithm.HmacMD5);
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getHMACDigest(secretKey, data.getBytes(), DigestAlgorithm.HmacMD5)));*/
        //HmacMD5 摘要

        /*byte[] hmacMD5SecretKey = DigestUtil.getHMACSecretKey(DigestAlgorithm.HmacSHA256);

        System.out.println(BytesToHex.fromBytesToHex(hmacMD5SecretKey));
        System.out.print(BytesToHex.fromBytesToHex(DigestUtil.getHMACDigest(hmacMD5SecretKey, data.getBytes(), DigestAlgorithm.HmacSHA256)));*/

        //甲方公钥
        byte[] publicKey1;
        //甲方私钥
        byte[] privateKey1;
        //甲方本地秘钥
        byte[] localKey1;
        //乙方公钥
        byte[] publicKey2;
        //乙方私钥
        byte[] privateKey2;
        //乙方本地秘钥
        byte[] localKey2;

        //初始化秘钥，并生成甲方秘钥对
        /*Map<String, Object> map1 = DHUtils.initKey();
        publicKey1 = DHUtils.getPublicKey(DHUtils.getPublicKey((PublicKey) map1.get(KeyUtil.PUBLIC_KEY)));
        privateKey1 = DHUtils.getPrivateKey(map1);

        //输出甲方公钥和私钥
        System.out.println("甲方公钥:" + BytesToHex.fromBytesToHex(publicKey1));
        System.out.println("甲方私钥:" + BytesToHex.fromBytesToHex(privateKey1));

        //初始化秘钥，并根据甲方公钥生成乙方密钥对
        Map<String, Object> map2 = DHUtils.initKey(publicKey1);
        publicKey2 = DHUtils.getPublicKey(map2);
        privateKey2 = DHUtils.getPrivateKey(map2);
        //输出乙方公钥和私钥
        System.out.println("乙方公钥:" + BytesToHex.fromBytesToHex(publicKey2));
        System.out.println("乙方私钥:" + BytesToHex.fromBytesToHex(privateKey2));

        //根据甲方公钥和乙方私钥生成乙方本地秘钥
        localKey2 = DHUtils.getSecretKey(publicKey1, privateKey2);
        System.out.println("乙方本地秘钥:" + BytesToHex.fromBytesToHex(localKey2));


        //根据甲方私钥和乙方公钥生成甲方本地密钥
        localKey1 = DHUtils.getSecretKey(publicKey2, privateKey1);
        System.out.println("甲方本地秘钥:" + BytesToHex.fromBytesToHex(localKey1));*/

        //RSA算法
        /*Map<String, Object> map = RSAUtil.initKey();
        byte[] publicKey = RSAUtil.getPublicKey(map);
        byte[] privateKey = RSAUtil.getPrivateKey(map);
        byte[] encryptData = RSAUtil.encryptData(RSAUtil.getPublicKey(publicKey), data.getBytes());
        System.out.println("加密后数据:" + BytesToHex.fromBytesToHex(encryptData));
        System.out.println("解密后数据:" + new String(RSAUtil.descryptData(RSAUtil.getPrivateKey(privateKey), encryptData)));*/

        //RSA签名
       /* Map<String, Object> keyMap = RSAUtil.initKey();
        byte[] publicKey = KeyUtil.getPublicKey((PublicKey) keyMap.get(KeyUtil.PUBLIC_KEY));
        byte[] privateKey = KeyUtil.getPrivateKey((PrivateKey) keyMap.get(KeyUtil.PRIVATE_KEY));
        byte[] sign = RSASignature.getInstance().sign(privateKey, data.getBytes());
        System.out.println("MD5withRSA signature:" + BytesToHex.fromBytesToHex(sign));
        boolean result = RSASignature.getInstance().verify(sign, data.getBytes(), publicKey);
        System.out.println("MD5withRSA sinature result:" + result);*/

        /*DSA签名*/
        Map<String, Object> keyMap = DSAUtil.initKey();
        byte[] publicKey = KeyUtil.getPublicKey((PublicKey) keyMap.get(KeyUtil.PUBLIC_KEY));
        byte[] privateKey = KeyUtil.getPrivateKey((PrivateKey) keyMap.get(KeyUtil.PRIVATE_KEY));
        byte[] sign = DSASignature.getInstance().sign(privateKey, data.getBytes());
        System.out.println("SHA1withRSA signature:" + BytesToHex.fromBytesToHex(sign));
        boolean result = DSASignature.getInstance().verify(sign, "jikexueyuan123".getBytes(), publicKey);
        System.out.println("SHA1withRSA sinature result:" + result);
    }

}
