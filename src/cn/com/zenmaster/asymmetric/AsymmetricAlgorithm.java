package cn.com.zenmaster.asymmetric;

/**
 * Created by TianYu on 2016/5/29.
 */
public enum AsymmetricAlgorithm {
    DH("DH"),RSA("RSA");

    private String value;

    AsymmetricAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
