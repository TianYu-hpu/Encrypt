package cn.com.zenmaster;

import cn.com.zenmaster.asymmetric.DHUtils;

import java.util.Map;

/**
 * Created by TianYu on 2016/5/29.
 */
public class Test {

    public static void main(String args[]) {
        String data = "jikexueyuan";

        //DES 加解密
       /* byte[] dessecretKey = DesUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(dessecretKey));
        byte[] encryptData = DesUtil.encryptData(dessecretKey, data.getBytes());
        System.out.println("des 加密" + BytesToHex.fromBytesToHex(encryptData));
        System.out.println("des 解密" + new String(DesUtil.descryptData(dessecretKey, encryptData)));*/

        // 3DES 加解密
       /* byte[] desedeSecretKey = DesedeUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(desedeSecretKey));
        byte[] encryptDataDesede = DesedeUtil.encryptData(desedeSecretKey, data.getBytes());
        System.out.println("3des 加密" + BytesToHex.fromBytesToHex(encryptDataDesede));
        System.out.println("3des 解密" + new String(DesedeUtil.descryptData(desedeSecretKey, encryptDataDesede)));*/

        // AES 加解密
        /*byte[] aesSecretKey = AesUtil.getInstance().getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(aesSecretKey));
        byte[] encryptDataAes = AesUtil.getInstance().encryptData(aesSecretKey, data.getBytes());
        System.out.println("aes 加密" + BytesToHex.fromBytesToHex(encryptDataAes));
        System.out.println("aes 解密" + new String(AesUtil.getInstance().descryptData(aesSecretKey, encryptDataAes)));*/

        //摘要算法
        /*System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getMD5Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA1Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA256Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA384Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA512Digest(data.getBytes())));*/

        //HmacMD5 摘要

       /* byte[] hmacMD5SecretKey = DigestUtil.getInstance().getHMACSecretKey(DigestAlgorithm.HmacSHA256.getValue());

        System.out.println(BytesToHex.fromBytesToHex(hmacMD5SecretKey));

        System.out.print(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getHMACDigest(hmacMD5SecretKey, data.getBytes(), DigestAlgorithm.HmacSHA256.getValue())));*/

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
        Map<String, Object> map1 = DHUtils.initKey();
        publicKey1 = DHUtils.getPublicKey(map1);
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
        System.out.println("甲方本地秘钥:" + BytesToHex.fromBytesToHex(localKey1));


    }

}
