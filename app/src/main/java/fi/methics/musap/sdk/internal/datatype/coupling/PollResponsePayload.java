package fi.methics.musap.sdk.internal.datatype.coupling;

import com.google.gson.annotations.SerializedName;

import fi.methics.musap.sdk.internal.datatype.MusapKey;
import fi.methics.musap.sdk.internal.sign.SignatureReq;
import fi.methics.musap.sdk.internal.keygeneration.KeyGenReq;

public class PollResponsePayload extends ResponsePayload {

    public static final String MODE_SIGN = "sign";
    public static final String MODE_GENSIGN = "generate-sign";
    public static final String MODE_GENONLY = "generate-only";

    @SerializedName("signaturepayload")
    private final SignaturePayload signaturePayload;

    @SerializedName("transid")
    private final String transId;

    /**
     * Get the mode of this poll response.
     * @return One of: "sign", "generate-sign", "generate-only"
     */
    public String getMode() {
        if (signaturePayload == null) return null;
        return signaturePayload.mode;
    }

    /**
     * Get the text to display to the user
     * @return Text to display
     */
    public String getDisplayText() {
        if (signaturePayload == null) return null;
        return signaturePayload.display;
    }

    /**
     * Get the raw Coupling API SignaturePayload
     * @return Raw SignaturePayload
     */
    public SignaturePayload getSignaturePayload() {
        return signaturePayload;
    }

    /**
     * Does this request ask for new key generation?
     * @return true if new key generation is wanted
     */
    public boolean shouldGenerateKey() {
        return !MODE_SIGN.equals(this.getMode());
    }

    /**
     * Does this request ask for a signature?
     * @return true if signature is asked
     */
    public boolean shouldSign() {
        return !MODE_GENONLY.equals(this.getMode());
    }

    public PollResponsePayload(SignaturePayload signaturePayload, String transId) {
        this.signaturePayload = signaturePayload;
        this.transId = transId;
    }

    /**
     * Get the poll response transaction id
     * @return transaction id
     */
    public String getTransId() {
        return this.transId;
    }

    public SignatureReq toSignatureReq(MusapKey key) {
        SignatureReq req = this.signaturePayload.toSignatureReq(key);
        req.setTransId(this.transId);
        return req;
    }

    public KeyGenReq toKeygenReq() {
        KeyGenReq req = this.signaturePayload.toKeygenReq();
        return req;
    }

}
