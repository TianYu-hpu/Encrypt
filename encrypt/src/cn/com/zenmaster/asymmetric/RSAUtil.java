package cn.com.zenmaster.asymmetric;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
public class RSAUtil extends KeyUtil {

    public static Map<String, Object> initKey() {
        Map<String, Object> map = null;
        try {
            //创建密钥对生成器
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance(AsymmetricAlgorithm.RSA);
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
    public static byte[] encryptData(RSAPublicKey publicKey, byte[] data) {
        byte[] bytes = null;
        try {
            //2. Cipher 完成加密工作
            Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm.RSA);
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
            Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm.RSA);
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
            KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.RSA);
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
            KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.RSA);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            rsaPrivateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return rsaPrivateKey;
    }

    /**
     * 对内容进行摘要
     * @param object
     * @return
     */
    public static String digest(Object object) {
        return DigestUtils.sha256Hex(JSON.toJSONString(object));
    }

    /**
     * 从字符串中加载私钥
     * @param privateKeyStr
     *            公钥数据字符串
     * @throws Exception
     *             加载私钥时产生的异常
     */
    public static RSAPrivateKey getPrivateKey(String privateKeyStr) throws Exception {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory
                    .generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (IOException e) {
            throw new Exception("私钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 从文件中加载私钥
     * @param privateKeyPath
     * @return
     * @throws Exception
     */
    public static RSAPrivateKey getRSAPrivateKey(String privateKeyPath) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(privateKeyPath));
        try {
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                if (readLine.charAt(0) == '-') {
                    continue;
                } else {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            return getPrivateKey(sb.toString());
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (Exception e) {
                throw new Exception("关闭输入缓存流出错");
            }
        }
    }

    /**
     * 从文件中输入流中加载公钥
     * @param publicKeyPath 公钥输入流
     * @throws Exception 加载公钥时产生的异常
     */
    public static RSAPublicKey getRSAPublicKey(String publicKeyPath) throws Exception {

        BufferedReader br = new BufferedReader(new FileReader(publicKeyPath));
        try {
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                if (readLine.charAt(0) == '-') {
                    continue;
                } else {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            return getPublicKey(sb.toString());
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (Exception e) {
                throw new Exception("关闭输入缓存流出错");
            }
        }
    }

    /**
     * 从字符串中加载公钥
     * @param publicKeyStr 公钥数据字符串
     * @throws Exception 加载公钥时产生的异常
     */
    public static RSAPublicKey getPublicKey(String publicKeyStr) throws Exception {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (IOException e) {
            throw new Exception("公钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 签名
     * @param plain
     * @param privateKey
     * @return
     */
    public static String sign(String plain, RSAPrivateKey privateKey) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(plain.getBytes("UTF-8"));
            byte[] byteBuffer = messageDigest.digest();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(byteBuffer);
            byte[] signedData = signature.sign();
            return new BASE64Encoder().encode(signedData);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("签名异常");
        }
    }

    /**
     * 签名
     * @param object
     * @param privateKey
     * @return
     */
    public static String sign(Object object, RSAPrivateKey privateKey) {
        return sign(JSON.toJSONString(object), privateKey);
    }




    /**
     * 验签
     * @param plain
     * @param signStr
     * @param publicKey
     * @return
     */
    public static boolean verify(String plain, String signStr, RSAPublicKey publicKey) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(plain.getBytes("UTF-8"));
            byte[] byteBuffer = messageDigest.digest();
            byte[] signedData = new BASE64Decoder().decodeBuffer(signStr);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(byteBuffer);
            if (signature.verify(signedData)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("验签异常");
        }
    }

    /**
     * 验签
     * @param object
     * @param signStr
     * @param publicKey
     * @return
     */
    public static boolean verify(Object object, String signStr, RSAPublicKey publicKey) {
        return verify(JSON.toJSONString(object), signStr, publicKey);
    }


    /**
     * 用于加密密钥
     * @param plain
     * @param publicKey
     * @return
     */
    public static String encrypt(String plain, RSAPublicKey publicKey) {
        try {
            //Cipher负责完成加密或解密工作，基于RSA
            Cipher cipher = Cipher.getInstance("RSA");
            //根据公钥，对Cipher对象进行初始化
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //加密，结果保存进resultBytes，并返回
            return new BASE64Encoder().encodeBuffer(cipher.doFinal(plain.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("加密异常");
        }
    }

    /**
     * 用于解密密钥
     * @param encryptStr
     * @param privateKey
     * @param charset
     * @return
     */
    public static String decrypt(String encryptStr, RSAPrivateKey privateKey, String charset) {
        try {
            byte[] encBytes = new BASE64Decoder().decodeBuffer(encryptStr);
            Cipher cipher = Cipher.getInstance("RSA");
            //根据私钥对Cipher对象进行初始化
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            //解密并将结果保存进resultBytes
            return new String(cipher.doFinal(encBytes), charset);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("解密异常");
        }
    }

    public static void main(String[] args) throws Exception {

//        String rsaPriKeyPath = "/Users/wangmingzhuo/Downloads/rsa_private_key_pkcs8.pem";
//        String rsaPubKeyPath = "/Users/wangmingzhuo/Downloads/rsa_public_key.pem";
//
//        String signStr = sign("abcd", getRSAPrivateKey(rsaPriKeyPath));
//        System.out.println(signStr);
//        boolean verifyResult = verify("abcd", signStr, getRSAPublicKey(rsaPubKeyPath));
//        System.out.println(verifyResult);
//
//        String encryptStr = encrypt("xiaoming", getRSAPublicKey(rsaPubKeyPath));
//        System.out.println(encryptStr);
//
//        String decryptStr = decrypt(encryptStr, getRSAPrivateKey(rsaPriKeyPath), "UTF-8");
//        System.out.println(decryptStr);
        //--------------------------------------

        String rsaPriKeyStr = "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDPmtoLtMVfE3FX" +
                "KkblnUGnNIlXaewAgQAyR6cJxDsdtAhc/lDxJBxDs7EAaLI0c3fk0KET9JpJ0ZUa" +
                "e8YsukMtrt7yt4pH+2HybRafTCwlGP9I8pae6HBesIlm18YdBRaQH0lw9LYIG6Od" +
                "asOI0KJaNq6ZO/0A6BH8ukszWvdZWWgnMQZByMOnl+Lm7k84jx5YldP73Ppi8Tmh" +
                "1X/dNqrhmons33OSXYiz6kE9qN861pQHyUO/4pKBMMiOIQR8XjmEIgj4cJD0s/Vn" +
                "CdGIkhvsViq1FXGOfqZydqqtGRMKMOcAseNxHPH8+wh3Mj0WNTHmyBtkfovtELPH" +
                "uRh/MKotAgMBAAECggEBAMvq6aQ38up5mYmpwCvH9HX9d64CH8s66ut4UA2azwpV" +
                "DSXys6S4+H5ToVeqfuhgRvLdLmsAhxBdKZzy2OyUJGpZ6ynzuIMN296Y4nCkDHSA" +
                "Ajkv91ytKbsIol3/MdzNY6U65hNqeuap52M3PEtFy0LblVJ0hwX97bUVc8pE3tLF" +
                "5r9qk6U8lJXkht4zwdyG0SE3RPL5qCkLpmOSwd6xzjiurteqMpG9FxpITRG1Z0+W" +
                "qaRqMpoXqo3zRUmy/1hK+U1a41mvtZvlO9QMKzAsJR8nzXsl0boTW6sQVIJI+QKo" +
                "2zfvq0OyUPs9ZdOV83hADCpgwjJcU/AQ0eUIaXIAnmECgYEA8mVH0vuDZ7Fy+vwk" +
                "5eRnHtNlRhlJy6CL5PhdFl0av91F0NKde04wuARHcXSABdxjujCnFaWJ90kZvW6c" +
                "AXLCXQECyUfdcmXl1H/dbBA6UPNZXAjOfh8xxVBF152tGeTEYczD6nnMonRz0X/h" +
                "MeV/zVfDd+V1s1hfFO8JhW+WoRkCgYEA20Gza+WxYeKU7ArMNfucDhtsqs++BTwM" +
                "LjicjT0Dbdk06AkgGSemkfldWuUeZNofuv7uIqYE3iaKfl8eqQNXEF9kvrQEtEZc" +
                "K3fj15+YyfQOe1S00bAYJtl8iG3CDu7EWVPP7UTOyGohvu4C/o8fzY+dbQd5KINu" +
                "cLAjDjWl0DUCgYEAslMccfUjCSgc5NSW+KH900nGGboE9k9YW8zz/r3kLf7FnAk2" +
                "Xj55zQco4CjK/oTSwWmFooE0bL5Ut24mS1J39yAFQrsiCUU5vgmLhjKyFFfTB8ha" +
                "0aJ1ZSnXF/ciIAiTCTgxcdDFYUa25gtkSucCDLliTlR7MMP0v1vT71zWvhECgYEA" +
                "0FVdZuiZ46ioWKDp6WFqpvzoBGXg6Jhl+oVQO+P9niMFYnVJSp2iaJHJYtTSTIH2" +
                "JHiXTdTySyPT9L/tIitKTwRVdd8XmTRB4AvLMtczFrIQEKAsMBJi4IdHDVs9SXMW" +
                "nspEh+8ZjNVLu1/s+HSGg4wyyaaQOS6pgenbZWUUaQECgYEAwLu9vTLtzYGQBvzl" +
                "yLepoRGR6Nb4GZhQmJzyfQzQqax1nlLHTNsLZihw84jIHTRAZVbLBoKOYl1Vq6P6" +
                "Zd2EhtHQVUKY13pD8SOemFYH/n7ZtP+xHJa7o+Ajmc4XH0RFQWfPw35NuR1iZ0C2" +
                "tqhQya88VrQtqo47DXKAiUBWCY4=";

        String rsaPubKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5raC7TFXxNxVypG5Z1B" +
                "pzSJV2nsAIEAMkenCcQ7HbQIXP5Q8SQcQ7OxAGiyNHN35NChE/SaSdGVGnvGLLpD" +
                "La7e8reKR/th8m0Wn0wsJRj/SPKWnuhwXrCJZtfGHQUWkB9JcPS2CBujnWrDiNCi" +
                "WjaumTv9AOgR/LpLM1r3WVloJzEGQcjDp5fi5u5POI8eWJXT+9z6YvE5odV/3Taq" +
                "4ZqJ7N9zkl2Is+pBPajfOtaUB8lDv+KSgTDIjiEEfF45hCII+HCQ9LP1ZwnRiJIb" +
                "7FYqtRVxjn6mcnaqrRkTCjDnALHjcRzx/PsIdzI9FjUx5sgbZH6L7RCzx7kYfzCq" +
                "LQIDAQAB";

        String num="6221213123123123123";
        System.out.println("元数据；"+num);
        String signStr = sign(num, getPrivateKey(rsaPriKeyStr));
        System.out.println("加密后"+signStr);
        boolean verifyResult = verify(num, signStr, getPublicKey(rsaPubKeyStr));
        System.out.println("验签："+verifyResult);




    }

}
