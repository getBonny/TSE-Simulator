package main.java.de.bsi;

import main.java.de.bsi.seapi.exceptions.*;
import main.java.de.bsi.tsesimulator.constants.ASN1Constants;
import main.java.de.bsi.tsesimulator.constants.Constants;
import main.java.de.bsi.tsesimulator.exceptions.*;
import main.java.de.bsi.tsesimulator.msg.TransactionLogMessage;
import main.java.de.bsi.tsesimulator.tlv.TLVObject;
import main.java.de.bsi.tsesimulator.utils.TR_03111_Utils;
import main.java.de.bsi.tsesimulator.utils.Utils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.ZonedDateTime;

import static main.java.de.bsi.tsesimulator.constants.Constants.ECDSA_PLAIN_SHA_384;

public class App {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PublicKey publicKey = getPublicKey();

        TransactionLogMessage trxLogMessage = new TransactionLogMessage();
        trxLogMessage.setVersion(0);
        trxLogMessage.setCertifiedDatatype(Constants.TRANSACTION_LOG_OID);
        trxLogMessage.setOperationtype("finishTransaction");
        trxLogMessage.setClientID("0CF54B11725");
        trxLogMessage.setProcessData("Beleg^49.99_0.00_0.00_0.00_0.00^49.99:Unbar".getBytes());
        trxLogMessage.setProcessType("Kassenbeleg-V1");
        trxLogMessage.setTransactionNumber(406967L);
        trxLogMessage.setSerialNumber(calculateSerialNumber(publicKey));
        trxLogMessage.setAlgorithm(ECDSA_PLAIN_SHA_384);

        //Signature Counter
        TLVObject signatureCounterElement = new TLVObject();
        signatureCounterElement.setTagWithByteElement(ASN1Constants.UNIVERSAL_INTEGER);
        signatureCounterElement.setValueWithLongElement(874925L);
        byte[] signatureCounterAsTLV = signatureCounterElement.toTLVByteArray();

        // Log Time
        TLVObject logTimeElement = new TLVObject();
        logTimeElement.setTagWithByteElement(ASN1Constants.UNIVERSAL_INTEGER);
        logTimeElement.setValueWithLongElement(ZonedDateTime.parse("2023-02-27T11:40:22.000Z").toEpochSecond());
        byte[] logTimeAsTLV = logTimeElement.toTLVByteArray();

        byte[] signatureReconstructed = Utils.concatAnyNumberOfByteArrays(trxLogMessage.toMinorTLVByteArray(), signatureCounterAsTLV, logTimeAsTLV);

        TLVObject signatureValueElement = new TLVObject();
        signatureValueElement.setTagWithByteElement(ASN1Constants.UNIVERSAL_OCTET_STRING);
        signatureValueElement.setValue(signatureReconstructed);
        byte[] signatureAsTLV = signatureValueElement.toTLVByteArray();
        byte[] lowerTransactionLogMessageByteArray=Utils.concatAnyNumberOfByteArrays(signatureCounterAsTLV,logTimeAsTLV, signatureAsTLV);
        byte[] upperTransactionLogMessageByteArray = trxLogMessage.toMinorTLVByteArray();

//        concat the upper and the lower part and store it in another byte array
        byte[] message = Utils.concatTwoByteArrays(upperTransactionLogMessageByteArray, lowerTransactionLogMessageByteArray);


        byte[] signatureOnReceipt = Base64.decode("EeucLEfm1f6MW6Hp1J8F+vuiXrVkC6dtNDSV5jsi5aRlt+KQQeLsQ0BQnkquJW9aNkWodr5zmHLZObtzb0WBReUed+q3/0beYLYYqGSxrDyOGCycQg928VA1vkSjVcPX");
        boolean valid = verify(signatureOnReceipt, signatureReconstructed, (ECPublicKey) publicKey);
        System.out.println("Is valid: " + valid);
        valid = verifySignature(publicKey, message, signatureOnReceipt);
        System.out.println("Is valid: " + valid);

    }

    private static PublicKey getPublicKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        // Beispiel: Base64-codierter öffentlicher Schlüssel (dein Base64-String hier einfügen)
        String base64PublicKey = "BCESZvlxgnvDUjdWA4lLrKsCsKXmnFkSIn9Hp70ov8Le+ST5oNHTiIJTF6ypPIwedE7k5DbJsDsmSScF7ivJHY0+B9ptVjkqkFh9XWv3VuEZnz0jG/VqnBTgp7Vt2l2x7g==";
        byte[] publicKeyBytes = Base64.decode(base64PublicKey);

        // Spezifikation der Kurve brainpoolP512r1
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolP384r1");

        // Den öffentlichen Punkt erzeugen
        org.bouncycastle.math.ec.ECPoint Q = ecSpec.getCurve().decodePoint(publicKeyBytes);

        // Erstellen des öffentlichen Schlüsselspezifikationsobjekts
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(Q, ecSpec);

        // Laden des KeyFactory-Objekts für ECDSA mit BouncyCastle
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

        // Erstellen des öffentlichen Schlüssels
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        return publicKey;
    }

    private static byte[] calculateSerialNumber(PublicKey pubKeyAsKey) {
        //get the public key that is used by the CryptoCore's signature algorithm
        //save the public key as a TLV encoded byte array
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


        //add the BC provider for good measure again (should already have been added, but better safe than sorry)
        Security.addProvider(new BouncyCastleProvider());
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
        System.out.println(bytesToHex(hashedPublicKey));
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

    public static boolean verify(byte[] signature, byte[] message, ECPublicKey publicKey) throws ECCException, TR_03111_ECC_V2_1_Exception {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolP384r1");
        boolean isVerified = false;
        //define everything that can be defined at this point of the program
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
            //TODO dynamic
            md = MessageDigest.getInstance("SHA3-384", "BC");
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

    public static boolean verifySignature(PublicKey publicKey, byte[] message, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance("SHA3-384withECDSA", "BC");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signatureBytes);
    }
}
