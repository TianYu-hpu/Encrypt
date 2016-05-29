package cn.com.zenmaster.digest;

/**
 * Created by TianYu on 2016/5/29.
 */
public enum DigestAlgorithm {
    MD5("MD5"),SHA("SHA-1"),SHA256("SHA-256"),SHA384("SHA-384"),SHA512("SHA-512")
    ,HmacMD5("HmacMD5"),HmacSHA("HmacSHA1"),HmacSHA256("HmacSHA256"),HmacSHA384("HmacSHA384")
    ,HmacSHA512("HmacSHA512");

    private String value;

    DigestAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
