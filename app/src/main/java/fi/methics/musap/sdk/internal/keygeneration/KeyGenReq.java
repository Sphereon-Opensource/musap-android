package fi.methics.musap.sdk.internal.keygeneration;

import android.app.Activity;
import android.view.View;

import java.util.ArrayList;
import java.util.List;

import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm;
import fi.methics.musap.sdk.internal.datatype.KeyAttribute;
import fi.methics.musap.sdk.internal.datatype.StepUpPolicy;
import fi.methics.musap.sdk.internal.discovery.KeyBindReq;

public class KeyGenReq {

    private String keyAlias;
    private String did;
    private String role;
    private String keyUsage;
    private StepUpPolicy stepUpPolicy;
    private List<KeyAttribute> attributes;
    private boolean userAuthenticationRequired;
    protected KeyAlgorithm keyAlgorithm;
    protected Activity activity;
    protected View view;

    protected KeyGenReq() {

    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public Activity getActivity() {
        return activity;
    }

    public View getView() {
        return view;
    }

    public KeyAlgorithm getAlgorithm() {
        return this.keyAlgorithm;
    }

    public String getDid() {
        return did;
    }

    public String getRole() {
        return role;
    }

    public StepUpPolicy getStepUpPolicy() {
        return stepUpPolicy;
    }

    public List<KeyAttribute> getAttributes() {
        return attributes;
    }

    public String getKeyUsage() {
        return this.keyUsage;
    }

    public boolean isUserAuthenticationRequired() {
        return userAuthenticationRequired;
    }

    public void setActivity(Activity activity) {
        this.activity = activity;
    }

    public void setView(View view) {
        this.view = view;
    }

    public void setKeyAlgorithm(KeyAlgorithm algorithm) {
        this.keyAlgorithm = algorithm;
    }


    public static class Builder {
        private String keyAlias;
        private String did;
        private String role;
        private String keyUsage;
        private StepUpPolicy stepUpPolicy;
        private List<KeyAttribute> attributes = new ArrayList<>();
        private KeyAlgorithm keyAlgorithm;
        private Activity activity;
        private View view;
        private boolean userAuthenticationRequired;

        public Builder setKeyAlias(String keyAlias) {
            this.keyAlias = keyAlias;
            return this;
        }

        public Builder setDid(String did) {
            this.did = did;
            return this;
        }

        public Builder setRole(String role) {
            this.role = role;
            return this;
        }

        public Builder setKeyUsage(String keyUsage) {
            this.keyUsage = keyUsage;
            return this;
        }

        public Builder setActivity(Activity activity) {
            this.activity = activity;
            return this;
        }

        public Builder setKeyAlgorithm(KeyAlgorithm keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            return this;
        }

        public Builder setStepUpPolicy(StepUpPolicy stepUpPolicy) {
            this.stepUpPolicy = stepUpPolicy;
            return this;
        }

        public Builder setUserAuthenticationRequired(boolean userAuthenticationRequired) {
            this.userAuthenticationRequired = userAuthenticationRequired;
            return this;
        }

        public Builder addAttribute(String key, String value) {
            this.attributes.add(new KeyAttribute(key, value));
            return this;
        }

        public Builder addAttribute(KeyAttribute attr) {
            this.attributes.add(attr);
            return this;
        }

        public Builder setView(View view) {
            this.view = view;
            return this;
        }

        public KeyGenReq createKeyGenReq() {
            KeyGenReq req = new KeyGenReq();
            req.keyAlias = keyAlias;
            req.keyUsage = keyUsage;
            req.did = did;
            req.attributes = attributes;
            req.stepUpPolicy = stepUpPolicy;
            req.role = role;
            req.keyAlgorithm = keyAlgorithm;
            req.activity = activity;
            req.view = view;
            req.userAuthenticationRequired = userAuthenticationRequired;
            return req;
        }

    }

}
