package jni;

import java.io.*;
import java.net.URL;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class LibraryLoader {
    public static String getExt() {
        String osName = System.getProperty("os.name");
        if (osName.equals("Linux"))
            return "so";
        else if (osName.equals("Mac OS X"))
            return "dylib";
        else
            return "dll";
    }

    public static Boolean load(Class<?> cls, String name) {
        String path = "/lib" + name + "." + getExt();
        URL url = cls.getResource(path);

        Boolean success = false;
        try {
            final File libfile = File.createTempFile(name, ".lib");
            libfile.deleteOnExit();

            final InputStream in = url.openStream();
            final OutputStream out = new BufferedOutputStream(new FileOutputStream(libfile));

            int len = 0;
            byte[] buffer = new byte[8192];
            while ((len = in.read(buffer)) > -1)
                out.write(buffer, 0, len);
            out.close();
            in.close();

            System.load(libfile.getAbsolutePath());
            success = true;
        } catch (IOException x) {

        }

        return success;
    }


    public static boolean loadAll(Class<?> cls, String name) throws Exception {
        // Load the os-dependent library from the jar file
        String nativeLibraryName = System.mapLibraryName(name);

        String nativeLibraryPath = "";

        if (cls.getResource(nativeLibraryPath + "/" + nativeLibraryName) == null) {
            throw new Exception("Error loading native library: " + nativeLibraryPath + "/" + nativeLibraryName);
        }

        // Temporary library folder
        String tempFolder = new File(System.getProperty("java.io.tmpdir")).getAbsolutePath();

        // Extract resource files
        return extractResourceFiles(nativeLibraryPath, nativeLibraryName, tempFolder);
    }


    private static boolean extractResourceFiles(String nativeLibraryPath, String nativeLibraryName,
                                                String tempFolder) throws IOException {
        String[] filenames = null;
        filenames = new String[] {
                "libcjson.so",
                "libdaabridgecpp.so",
                "libamcl_bls_FP256BN.so",
                "libamcl_core.so",
                "libamcl_curve_FP256BN.so",
                "libamcl_mpin_FP256BN.so",
                "libamcl_pairing_FP256BN.so",
                "libamcl_rsa_2048.so",
                "libamcl_rsa_3072.so",
                "libamcl_rsa_4096.so",
                "libamcl_wcc_FP256BN.so",
                "libamcl_x509.so",
                "libcjson.so",
                "libcrypto.so",
                "libibmtss.so",
                "libssl.so"
        };

        boolean ret = true;

        for (String file : filenames) {
            ret &= extractAndLoadLibraryFile(nativeLibraryPath, file, tempFolder);
        }

        return ret;
    }

    private static synchronized boolean loadNativeLibrary(String path, String name) {
        File libPath = new File(path, name);
        if (libPath.exists()) {
            try {
                System.load(new File(path, name).getAbsolutePath());
                return true;
            } catch (UnsatisfiedLinkError e) {
                System.err.println(e);
                return false;
            }

        } else
            return false;
    }


    private static boolean extractAndLoadLibraryFile(String libFolderForCurrentOS, String libraryFileName,
                                                     String targetFolder) {
        String nativeLibraryFilePath = libFolderForCurrentOS + "/" + libraryFileName;

        String extractedLibFileName = libraryFileName;
        File extractedLibFile = new File(targetFolder, extractedLibFileName);

        try {
            // Extract file into the current directory
            InputStream reader = DAAInterface.class.getResourceAsStream(nativeLibraryFilePath);
            FileOutputStream writer = new FileOutputStream(extractedLibFile);
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            while ((bytesRead = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, bytesRead);
            }

            writer.close();
            reader.close();

            if (!System.getProperty("os.name").contains("Windows")) {
                try {
                    Runtime.getRuntime().exec(new String[] { "chmod", "755", extractedLibFile.getAbsolutePath() })
                            .waitFor();
                } catch (Throwable e) {
                }
            }

            return loadNativeLibrary(targetFolder, extractedLibFileName);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            return false;
        }

    }


}