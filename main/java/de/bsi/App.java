package main.java.de.bsi;

import main.java.de.bsi.tsesimulator.constants.Constants;
import main.java.de.bsi.tsesimulator.exceptions.ECCException;
import main.java.de.bsi.tsesimulator.exceptions.TLVException;
import main.java.de.bsi.tsesimulator.exceptions.TR_03111_ECC_V2_1_Exception;
import main.java.de.bsi.tsesimulator.msg.TransactionLogMessage;
import main.java.de.bsi.tsesimulator.tlv.TLVObject;
import main.java.de.bsi.tsesimulator.utils.TR_03111_Utils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.ZonedDateTime;

import static main.java.de.bsi.tsesimulator.constants.Constants.ECDSA_PLAIN_SHA_384;

public class App {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] signatureOnReceipt = Base64.decode("EeucLEfm1f6MW6Hp1J8F+vuiXrVkC6dtNDSV5jsi5aRlt+KQQeLsQ0BQnkquJW9aNkWodr5zmHLZObtzb0WBReUed+q3/0beYLYYqGSxrDyOGCycQg928VA1vkSjVcPX");
        ECPublicKey publicKey = getPublicKey("BCESZvlxgnvDUjdWA4lLrKsCsKXmnFkSIn9Hp70ov8Le+ST5oNHTiIJTF6ypPIwedE7k5DbJsDsmSScF7ivJHY0+B9ptVjkqkFh9XWv3VuEZnz0jG/VqnBTgp7Vt2l2x7g==");

        int version = 2;
        // certifiedDataType
        String operationType = "FinishTransaction";
        String clientId = "0CF54B11725";
        String processData = "Beleg^49.99_0.00_0.00_0.00_0.00^49.99:Unbar";
        String processType = "Kassenbeleg-V1";
        int transactionNumber = 406967;
        int signatureCounter = 874925;
        long logTime = ZonedDateTime.parse("2023-02-27T11:40:33.000Z").toEpochSecond();
        byte[] serialnumber = calculateSerialNumber(publicKey);
        System.out.println("SerialNumber as Hex: " + bytesToHex(serialnumber));

        // --------------------------------------------------------------------------------------------------------------
        // According to TR-03151.pdf we need to concatenate several values:
        // message M := version||certifiedDataType||certifiedData||serialNumber||signatureAlgorithm||seAuditData||signatureCounter||logTime
        // verificationResult := VerifySignatureFunction (keypublic, sig, M, signatureAlgorithm)

        ASN1EncodableVector trxLogMessageVector = new ASN1EncodableVector();
        trxLogMessageVector.add(new ASN1Integer(version));
        trxLogMessageVector.add(new ASN1ObjectIdentifier(Constants.TRANSACTION_LOG_OID));
        trxLogMessageVector.add(new DERTaggedObject(false, 0x80, new DERPrintableString(operationType))); // Tag 0x80
        trxLogMessageVector.add(new DERTaggedObject(false, 0x81, new DERPrintableString(clientId)));      // Tag 0x81
        trxLogMessageVector.add(new DERTaggedObject(false, 0x82, encodeIndefiniteLength(processData)));    // Tag 0x82
        trxLogMessageVector.add(new DERTaggedObject(false, 0x83, new DERPrintableString(processType)));    // Tag 0x83
        trxLogMessageVector.add(new DERTaggedObject(false, 0x85, new ASN1Integer(transactionNumber)));
        trxLogMessageVector.add(new DEROctetString(serialnumber));
        ASN1EncodableVector signatureAlgorithmSeq = new ASN1EncodableVector();
        signatureAlgorithmSeq.add(new ASN1ObjectIdentifier(ECDSA_PLAIN_SHA_384));
        ASN1Sequence signatureAlgorithm = new DERSequence(signatureAlgorithmSeq);
        trxLogMessageVector.add(signatureAlgorithm);
        trxLogMessageVector.add(new ASN1Integer(signatureCounter));
        trxLogMessageVector.add(new ASN1Integer(logTime));

        // Erstelle die SEQUENCE für die gesamte Log Message
//        ASN1Sequence logMessage = new DERSequence(trxLogMessageVector);
        // Konvertiere die ASN.1-Daten in ein Byte-Array (DER-encoded)
//        byte[] message = logMessage.getEncoded();

        TransactionLogMessage transactionLogMessage = new TransactionLogMessage(clientId, processData.getBytes(), processType, null, transactionNumber, serialnumber);
        transactionLogMessage.setOperationtype(operationType);
        transactionLogMessage.setAlgorithm(ECDSA_PLAIN_SHA_384);
        byte[] result2 = transactionLogMessage.toMinorTLVByteArray();
        result2 = concatenate(result2, trxLogMessageVector.get(9).toASN1Primitive().getEncoded());
        result2 = concatenate(result2, trxLogMessageVector.get(10).toASN1Primitive().getEncoded());

        saveDERFile(result2, "message.der");
//        ASN1Primitive asn1Object = logMessage.toASN1Primitive();
//        System.out.println(ASN1Dump.dumpAsString(asn1Object, true));

        // --------------------------------------------------------------------------------------------------------------

//        listAllAlgorithms();
        boolean validSimple = verifySignature(publicKey, result2, signatureOnReceipt);
        System.out.println("Is valid: " + validSimple);
    }

    public static void saveDERFile(byte[] data, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }

    private static ECPublicKey getPublicKey(String base64PublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] publicKeyBytes = Base64.decode(base64PublicKey);
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolP384r1");
        org.bouncycastle.math.ec.ECPoint Q = ecSpec.getCurve().decodePoint(publicKeyBytes);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(Q, ecSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        return (ECPublicKey) publicKey;
    }

    private static byte[] extractPubKeyContent(PublicKey pubKeyAsKey) {
        byte[] wholePubKeyInfoByte = pubKeyAsKey.getEncoded();
        //decode that TLV encoded byte array to a TLVObject array
        TLVObject[] wholePubKeyInfoTLV = null;
        try {
            wholePubKeyInfoTLV = TLVObject.decodeASN1ByteArrayToTLVObjectArray(wholePubKeyInfoByte);
        } catch (TLVException e1) {
            e1.printStackTrace();
        }

        //the last value in the TLVObject array should be the public key
        byte[] publicKeyValueWithLeadingZeroes = wholePubKeyInfoTLV[wholePubKeyInfoTLV.length-1].getValue();

        //from comparing the last value with the value openssl declares as the public key it's obvious that this public key is
        //padded with leading zeroes and seems to always have a 04, signifying uncompressed encoding after the 00.
        //so let's get rid of those leading zeroes!
        byte[] publicKeyValue = new byte[publicKeyValueWithLeadingZeroes.length-1];
        System.arraycopy(publicKeyValueWithLeadingZeroes, 1, publicKeyValue, 0, publicKeyValue.length);
        return publicKeyValue;
    }

    private static byte[] calculateSerialNumber(PublicKey pubKeyAsKey) {
        //get the public key that is used by the CryptoCore's signature algorithm
        //save the public key as a TLV encoded byte array
        byte[] publicKeyValue = extractPubKeyContent(pubKeyAsKey);


        //add the BC provider for good measure again (should already have been added, but better safe than sorry)
        MessageDigest md = null;
        try {
            //get a SHA256 message digest from the bouncycastle provider
            md = MessageDigest.getInstance("SHA256", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        //feed the publicKeyValue to the message digest
        md.update(publicKeyValue);
        byte[] hashedPublicKey = md.digest();

        return hashedPublicKey;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0'); // fügt führende Null hinzu, wenn nötig
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }


    public static boolean verifySignature(PublicKey publicKey, byte[] message, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance("SHA384WITHPLAIN-ECDSA", "BC");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }

    public static void listAllAlgorithms(){
        // Alle registrierten Security Provider auflisten
        for (Provider provider : Security.getProviders()) {
            System.out.println("Provider: " + provider.getName());
            for (Provider.Service service : provider.getServices()) {
                if (service.getType().equals("MessageDigest")) {
                    System.out.println(" - Hash Algorithm: " + service.getAlgorithm());
                }
                if (service.getType().equals("Signature")) {
                    System.out.println(" - Signature Algorithm: " + service.getAlgorithm());
                }
            }
        }
    }

    private static ASN1OctetString encodeIndefiniteLength(String processData) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(processData.getBytes());  // Schreibe den Prozess-Dateninhalt
        baos.write(0x00);  // End-Of-Contents Marker für indefinite length encoding
        baos.write(0x00);
        return new BEROctetString(baos.toByteArray());  // BEROctetString für indefinite length
    }

    private static boolean verifyECDSASignature(byte[] publicKeyValue, byte[] message, byte[] signatureBytes) throws Exception {
        // Verwende die elliptische Kurve brainpoolP384r1 als Beispiel
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolP384r1");

        // Erstelle den ECPoint aus dem extrahierten Public Key-Wert
        ECPoint Q = ecSpec.getCurve().decodePoint(publicKeyValue);
        ECDomainParameters domainParams = new ECDomainParameters(
                ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH(), ecSpec.getSeed()
        );

        // Initialisiere den Public Key-Parameter für die Verifizierung
        ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(Q, domainParams);

        // Erstelle den ECDSA-Signer
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, pubKeyParams);


        // Erstelle den Hash der Nachricht (SHA-384)
        SHA384Digest digest = new SHA384Digest();
        digest.update(message, 0, message.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        // Splitte die Signatur in R und S (ECDSA Signatur besteht aus zwei Werten: R und S)
        byte[] r = Arrays.copyOfRange(signatureBytes, 0, signatureBytes.length / 2);
        byte[] s = Arrays.copyOfRange(signatureBytes, signatureBytes.length / 2, signatureBytes.length);

        // Verifiziere die Signatur (R und S)
        return signer.verifySignature(hash, new BigInteger(1, r), new BigInteger(1, s));
    }

    public static byte[] concatenate(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static boolean verify(ECPublicKey publicKey, byte[] message, byte[] signature) throws ECCException, TR_03111_ECC_V2_1_Exception {
        boolean isVerified = false;
        //define everything that can be defined at this point of the program
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolP384r1");
        BigInteger n = ecSpec.getN();										//domain parameter n
        BigInteger nMinusOne = ecSpec.getN().subtract(BigInteger.ONE); 		//nMinusOne = domain parameter n minus 1
        ECPoint generatorG = ecSpec.getG();									//domain parameter G
        BigInteger p = ecSpec.getCurve().getField().getCharacteristic(); 	//domain parameter p


        int tau = n.bitLength(); 								//tau is the bit length of the order of the base point. tau = log2(n)

        //get the length of each byte array of r and s
        //should be signature.length / 2
        if((signature.length % 2) != 0) {
            throw new ECCException("total length of r and s combined should be an even value.");
        }
        int l = signature.length / 2;

        //1.a split the signature into its components r and s
        byte[] rAsByteArray = new byte[l];
        byte[] sAsByteArray = new byte[l];
        System.arraycopy(signature, 0, rAsByteArray, 0, rAsByteArray.length);
        System.arraycopy(signature, (rAsByteArray.length), sAsByteArray, 0, sAsByteArray.length);

        //1.b turn rAsByteArray and sAsByteArray into BigIntegers
        BigInteger r = TR_03111_Utils.OS2BigInt(rAsByteArray);
        BigInteger s = TR_03111_Utils.OS2BigInt(sAsByteArray);

        //2. verify that r, s e {1,2,...,n−1}
        //r >= 1
        boolean b1= r.compareTo(BigInteger.ONE) >=0 ;
        //r <= n-1
        boolean b2 = r.compareTo(nMinusOne) <= 0;
        //s >= 1
        boolean b3 = s.compareTo(BigInteger.ONE) >= 0;
        //s <= n-1
        boolean b4 = s.compareTo(nMinusOne) <= 0;

        //if r OR s fail to verify, output false
        if((!b1) || (!b2) || (!b3) || (!b4)) {
            System.out.println("INFO: signature verification failed because\nb1: " +b1 +"  b2 " +b2 +"  b3 " +b3 +"  b4 " +b4);
            return false;
        }

        //3. calculate sInverse = s.modInverse(n)
        BigInteger sInverse = s.modInverse(n);

        //4. calculate u1 and u2
        //4.a calculate u1=sinv·OS2I(Hτ(M)) mod n
        //4.a.a calculate Hτ(M) aka hash truncated to the length of tau of the message m
        MessageDigest md = null;

        try {

            md = MessageDigest.getInstance("SHA3-384", BouncyCastleProvider.PROVIDER_NAME);
            //check, if length of the output of the hash function in bits < bit length of the order of the base point
            //if yes, that is illegal according to BSI TR-03111 V2.1
            if((md.getDigestLength()*8) < tau) {
                throw new TR_03111_ECC_V2_1_Exception("The length of the hash function SHOULD NOT be chosen so that digestBitLength < tau");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        md.update(message);
        byte[] hashByteArray = md.digest();
        //truncate the hashByteArray
        byte[] truncatedhashByteArray = TR_03111_Utils.truncatedleftmostBits(hashByteArray, tau);

        //4.a.b turn (Hτ(M)) into a BigInteger
        BigInteger hashTauMessage = TR_03111_Utils.OS2BigInt(truncatedhashByteArray);

        //4.a.c calculate u1 = sInverse * hashTauMessage
        BigInteger u1 = sInverse.multiply(hashTauMessage);
        u1 = u1.mod(n);

        //4.b calculate u2=sinv·r mod n
        BigInteger u2 = sInverse.multiply(r);
        u2 = u2.mod(n);

        //5. calculate Q = [u1]*G + [u2]*PA
        //5.a calculate u1TimesG
        ECPoint u1TimesG = generatorG.multiply(u1);
        u1TimesG = u1TimesG.normalize(); 						//normalize u1 * G

        //5.b calculate u2 * PA
        ECPoint Pa = publicKey.getQ(); 		//get the public point from the public key
        ECPoint u2TimesPA = Pa.multiply(u2);
        u2TimesPA = u2TimesPA.normalize(); 						//normalize u2 * PA

        //5.c calculate u1TimesG + u2TimesPA
        ECPoint Q = u1TimesG.add(u2TimesPA);
        Q = Q.normalize();

        //5.d check if Q == PointInfinity
        if(Q.isInfinity()) {
            return false;
        }

        //6. calculate v=OS2I(FE2OS(xQ)) mod n
        //6.a calculate FE2OS(xQ)
        BigInteger xCoordinateQ = Q.getAffineXCoord().toBigInteger();
        byte[] xQ = TR_03111_Utils.FE2OS(xCoordinateQ, p);

        //6.b calculate OS2I(FE2OS(xQ)) mod n
        BigInteger v = TR_03111_Utils.OS2BigInt(xQ);
        v = v.mod(n);

        //7. if v == r return true
        if(v.equals(r)) {
            return true;
        }

        return isVerified;
    }
}
