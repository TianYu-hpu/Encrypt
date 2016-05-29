package cn.com.zenmaster.symmetric;

/**
 * Created by TianYu on 2016/5/29.
 */
public enum SymmetricAlgorithm {

    DES("DES"),DES3("DESede"),AES("AES");


    private String value;

    SymmetricAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
