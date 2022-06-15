package jni;

public class Runner {
    public static void main(String[] args) {
//        Tools tools = new Tools();
//        System.out.println(tools.foo() + tools.bar());

        DAAInterface daa = new DAAInterface();

        String ik = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4CwPPzL9DS6n2zcDsV1hOadgL25Q\n" +
                "hTF3PuomKkE3/ET4GcPMTkYi8zd2IIUVI/FwY+sWTyHhCxrHkfXKksSAmA==\n" +
                "-----END PUBLIC KEY-----";

        String ik_priv = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIF8Cx/viWSyi0gCp/OcbMFJrbKmzO2PwlqA/RNtv9UMZoAoGCCqGSM49\n" +
                "AwEHoUQDQgAE4CwPPzL9DS6n2zcDsV1hOadgL25QhTF3PuomKkE3/ET4GcPMTkYi\n" +
                "8zd2IIUVI/FwY+sWTyHhCxrHkfXKksSAmA==\n" +
                "-----END EC PRIVATE KEY-----\n";


        byte[] issuerPk = ik.getBytes();
        byte[] issuerPriv = ik_priv.getBytes();


        System.out.println( daa.bar() );

//        daa.registerIssuerPK(issuerPk);
//        daa.registerIssuer_priv(issuerPriv);


    }
}