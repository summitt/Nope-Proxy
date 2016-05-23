package josh.nonHttp;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;


public  class JCESigner implements ContentSigner {

    private static final AlgorithmIdentifier PKCS1_SHA256_WITH_RSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));

    private Signature signature;
    private ByteArrayOutputStream outputStream;

    public JCESigner(PrivateKey privateKey, String signatureAlgorithm) {
        if (!"SHA256withRSA".equals(signatureAlgorithm)) {
            throw new IllegalArgumentException("Signature algorithm \"" + signatureAlgorithm + "\" not yet supported");
        }
        try {
            this.outputStream = new ByteArrayOutputStream();
            this.signature = Signature.getInstance(signatureAlgorithm);
            this.signature.initSign(privateKey);
        } catch (GeneralSecurityException gse) {
            throw new IllegalArgumentException(gse.getMessage());
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        if (signature.getAlgorithm().equals("SHA256withRSA")) {
            return PKCS1_SHA256_WITH_RSA_OID;
        } else {
            return null;
        }
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            signature.update(outputStream.toByteArray());
            return signature.sign();
        } catch (GeneralSecurityException gse) {
            gse.printStackTrace();
            return null;
        }
    }
}