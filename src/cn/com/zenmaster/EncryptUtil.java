package cn.com.zenmaster;

/**
 * Created by TianYu on 2016/5/29.
 */
public abstract class EncryptUtil {

    /**
     * 获取指定对称加密的秘钥
     *
     * @return
     */
    abstract byte[] getSecretKey();

    /** 加密
     *
     * @param key
     * @param data
     * @return
     */
    abstract byte[] encryptData(byte[] key, byte[] data);

    /** 解密
     *
     * @param key
     * @param data
     * @return
     */
    abstract byte[] descryptData(byte[] key, byte[] data);

}
