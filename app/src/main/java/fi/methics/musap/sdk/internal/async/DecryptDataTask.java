package fi.methics.musap.sdk.internal.async;

import android.content.Context;
import fi.methics.musap.sdk.api.MusapCallback;
import fi.methics.musap.sdk.api.MusapException;
import fi.methics.musap.sdk.internal.encryption.DecryptionReq;
import fi.methics.musap.sdk.internal.util.AsyncTaskResult;
import fi.methics.musap.sdk.internal.util.MusapAsyncTask;
import fi.methics.musap.sdk.internal.util.MusapSscd;

import java.util.concurrent.Semaphore;

public class DecryptDataTask extends MusapAsyncTask<byte[]> {

    private final DecryptionReq req;

    public DecryptDataTask(MusapCallback<byte[]> callback, Context context, Semaphore semaphore, DecryptionReq req) {
        super(callback, context);
        this.req  = req;
    }

    @Override
    protected AsyncTaskResult<byte[]> runOperation() throws MusapException {
        try {
            final MusapSscd sscd = req.getKey().getSscd();
            final byte[] decData = sscd.decryptData(req);
            return new AsyncTaskResult<>(decData);
        } catch (MusapException e) {
            throw e;
        }  catch (Exception e) {
            throw new MusapException(e);
        }
    }
}
