package fi.methics.musap.sdk.internal.encryption;

import fi.methics.musap.sdk.internal.datatype.MusapKey;

public class DecryptionReq {
    private final MusapKey key;
    private final byte[] data;
    private final byte[] salt;

    private DecryptionReq(Builder builder) {
        this.key = builder.key;
        this.data = builder.data;
        this.salt = builder.salt;
    }

    public MusapKey getKey() {
        return key;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getSalt() {
        return salt;
    }

    public static class Builder {
        private MusapKey key;
        private byte[] data;
        private byte[] salt;
        
        public Builder setKey(MusapKey key) {
            this.key = key;
            return this;
        }

        public Builder setData(byte[] data) {
            this.data = data;
            return this;
        }

        public Builder setSalt(byte[] salt) {
            this.salt = salt;
            return this;
        }

        public DecryptionReq build() {
            return new DecryptionReq(this);
        }
    }
}
