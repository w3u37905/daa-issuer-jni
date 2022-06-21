package jni;

public class DAAInterface {
    static {
//        if (!LibraryLoader.load(DAAInterface.class, "daabridgecpp"))
//            System.loadLibrary("daabridgecpp");

        try {
            //LibraryLoader.loadAll(DAAInterface.class, "daabridgecpp");
            LibraryLoader.load(DAAInterface.class, "daabridgecpp");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public native String bar();

    public native void registerWalletPK(byte[] pemFile);

    public native void registerWallet_priv(byte[] pemFile);

    public native void registerIssuerPK(byte[] pemFile);

    public native void registerIssuer_priv(byte[] pemFile);

    // DAA functionality for Registration
    public native String DAAEnable(); // Step 1

    public native String CreateEnableResponse(byte[] signedNonce); // Step 2

    public native String HandleIssuerChallenge(String issuerChallenge); // Step 4

    public native int verifySignature(String jsonSignature, byte[] message);

    public native void EnableDAACredential(String fullcre); // Step 6

    public native byte[] startDAASession();

    public native String DAASign(byte[] data, byte[] signedNonce);

    // Issuer "interface", basically just converts between JSON and objects: Can be implemented in real issuer
    public native byte[] prepareEnableResponse(String json); // Simulates Wallet signing, and then call CreateEnableResponse with this

    public native String getIssuerChallenge(String json_nonce_and_ek);

    public native String sendChallengeResponse(String cr);

    public native byte[] walletDoMeASignPlz(byte[] nonce); // Simulates Wallet signing, and then call CreateEnableResponse with this

}
