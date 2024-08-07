package fi.methics.musap.sdk.internal.async;

import android.content.Context;
import fi.methics.musap.sdk.api.MusapCallback;
import fi.methics.musap.sdk.api.MusapException;
import fi.methics.musap.sdk.internal.encryption.EncryptionReq;
import fi.methics.musap.sdk.internal.util.AsyncTaskResult;
import fi.methics.musap.sdk.internal.util.MusapAsyncTask;
import fi.methics.musap.sdk.internal.util.MusapSscd;

import java.util.concurrent.Semaphore;

public class EncryptDataTask extends MusapAsyncTask<byte[]> {

    private final EncryptionReq req;

    public EncryptDataTask(MusapCallback<byte[]> callback, Context context, Semaphore semaphore, EncryptionReq req) {
        super(callback, context);
        this.req  = req;
    }

    @Override
    protected AsyncTaskResult<byte[]> runOperation() throws MusapException {
        try {
            final MusapSscd sscd = req.getKey().getSscd();
            final byte[] encData = sscd.encryptData(req);
            return new AsyncTaskResult<>(encData);
        } catch (MusapException e) {
            throw e;
        }  catch (Exception e) {
            throw new MusapException(e);
        }
    }
}
