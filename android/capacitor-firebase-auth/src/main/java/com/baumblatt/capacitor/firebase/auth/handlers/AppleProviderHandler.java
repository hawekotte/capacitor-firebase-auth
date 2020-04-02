package com.baumblatt.capacitor.firebase.auth.handlers;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;

import com.baumblatt.capacitor.firebase.auth.CapacitorFirebaseAuth;
import com.baumblatt.capacitor.firebase.auth.R;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.OAuthCredential;
import com.google.firebase.auth.OAuthProvider;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.getcapacitor.JSObject;
import com.getcapacitor.PluginCall;
import com.google.firebase.auth.AuthCredential;

import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.TwitterAuthProvider;
import com.twitter.sdk.android.core.Callback;
import com.twitter.sdk.android.core.Result;
import com.twitter.sdk.android.core.Twitter;
import com.twitter.sdk.android.core.TwitterAuthConfig;
import com.twitter.sdk.android.core.TwitterConfig;
import com.twitter.sdk.android.core.TwitterCore;
import com.twitter.sdk.android.core.TwitterException;
import com.twitter.sdk.android.core.TwitterSession;
import com.twitter.sdk.android.core.identity.TwitterLoginButton;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;


public class AppleProviderHandler extends Activity implements ProviderHandler {

    private static final String APPLE_TAG = "AppleProviderHandler";
    private static final String TAG = "TEST";

    private String identityToken;
    private String nonce;

    private CapacitorFirebaseAuth plugin;
    private FirebaseAuth mAuth;
    private Context context;

    private final List<AuthCredential> credentialContainer = new ArrayList<>();
    private final List<Exception> errorContainer = new ArrayList<>();
    private final AtomicReference<String> idTokenReference = new AtomicReference();
    private final Semaphore semaphore = new Semaphore(0);

    @Override
    public void init(final CapacitorFirebaseAuth plugin) {
        this.plugin = plugin;
        this.mAuth = FirebaseAuth.getInstance();
        // TODO
    }

    @Override
    public void setContext(Context context) {
      this.context = context;
    }

    @Override
    public void signIn(PluginCall call) {
        // TODO

        // NOTE: This below uses the Firebase login flow and thus if we get the appleIDtoken from the auth result below
        //       we might actually be signing in twice... So we might have to handle the auth flow ourselves :(

        // Setup the provider and scopes we want

        OAuthProvider.Builder provider = OAuthProvider.newBuilder("apple.com");
        List<String> scopes =
            new ArrayList<String>() {
                {
                    add("email");
                    add("name");
                }
            };
        provider.setScopes(scopes);

        // Check to make sure nothing is pending
        Task<AuthResult> pending = this.mAuth.getPendingAuthResult();
        if (pending != null) {
            pending.addOnSuccessListener(new OnSuccessListener<AuthResult>() {
                @Override
                public void onSuccess(AuthResult authResult) {
                    Log.d(TAG, "checkPending:onSuccess:" + authResult);
                    // Get the user profile with authResult.getUser() and
                    // authResult.getAdditionalUserInfo(), and the ID
                    // token from Apple with authResult.getCredential().

                    // Call back to get stuff going
                    OAuthCredential credential = (OAuthCredential) authResult.getCredential();

                    // Store the credentials and let stuff know we can continue
                    credentialContainer.add(credential);
                    idTokenReference.set(credential.getIdToken());
                    semaphore.release();
                    return;

                }
            }).addOnFailureListener(new OnFailureListener() {
                @Override
                public void onFailure(@NonNull Exception e) {
                    Log.w(TAG, "checkPending:onFailure", e);
                    errorContainer.add(e);
                    semaphore.release();
                    return;
                }
            });
        } else {
            Log.d(TAG, "pending: null");

            // Start the sign in flow
            this.mAuth.startActivityForSignInWithProvider((Activity)this.context, provider.build())
              .addOnSuccessListener(
                new OnSuccessListener<AuthResult>() {
                  @Override
                    public void onSuccess(AuthResult authResult) {
                        // Sign-in successful!
                        Log.d(TAG, "activitySignIn:onSuccess:" + authResult.getUser());
                        // FirebaseUser user = authResult.getUser();
                        // ...

                        // Call back to get stuff going
                        OAuthCredential credential = (OAuthCredential) authResult.getCredential();

                        // Store the credentials and let stuff know we can continue
                        credentialContainer.add(credential);
                        idTokenReference.set(credential.getIdToken());
                        semaphore.release();
                        return;
                    }
                })
              .addOnFailureListener(
                new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        Log.w(TAG, "activitySignIn:onFailure", e);
                        errorContainer.add(e);
                        semaphore.release();
                        return;
                    }
                });
        };

        // Now wait for stuff to complete
      try {
        this.semaphore.acquire();
        // Make sure we didn't hit any errors
        if (this.errorContainer.size() > 0) {
          this.plugin.handleFailure("Apple Sign In failure:", this.errorContainer.get(0));
        } else {
          // Do the stuffs
          this.identityToken = this.idTokenReference.get();
          this.nonce = this.generateNonce(32);
          this.plugin.handleAuthCredentials(this.credentialContainer.get(0));
        }
      } catch(InterruptedException e) {
        this.plugin.handleFailure("Apple Sign In failure (interrupted):", this.errorContainer.get(0));
      }
    }

    private String generateNonce(int length) {
        SecureRandom generator = new SecureRandom();

        CharsetDecoder charsetDecoder = StandardCharsets.US_ASCII.newDecoder();
        charsetDecoder.onUnmappableCharacter(CodingErrorAction.IGNORE);
        charsetDecoder.onMalformedInput(CodingErrorAction.IGNORE);

        byte[] bytes = new byte[length];
        ByteBuffer inBuffer = ByteBuffer.wrap(bytes);
        CharBuffer outBuffer = CharBuffer.allocate(length);
        while (outBuffer.hasRemaining()) {
            generator.nextBytes(bytes);
            inBuffer.rewind();
            charsetDecoder.reset();
            charsetDecoder.decode(inBuffer, outBuffer, false);
        }
        outBuffer.flip();
        return outBuffer.toString();
    }

    @Override
    public int getRequestCode() {
        // return TwitterAuthConfig.DEFAULT_AUTH_REQUEST_CODE;

        // TODO -- Needed?
      return -1;
    }

    @Override
    public void handleOnActivityResult(int requestCode, int resultCode, Intent data) {
        // TODO
    }

    @Override
    public boolean isAuthenticated() {
        // TODO
        return false;
    }

    @Override
    public void fillResult(JSObject jsResult) {
        jsResult.put("identityToken", this.identityToken);
        jsResult.put("nonce", this.nonce);
    }

    @Override
    public void signOut() {
        // Not applicable here since Apple requires revocation rather than sign out
    }
}
