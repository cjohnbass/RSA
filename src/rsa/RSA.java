/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Random;

/**
 *
 * @author Christopher Bass
 */
public class RSA {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        RSA rsa = new RSA();

        // generate pub and priv keys
        BigInteger p = rsa.genRandomPrime(512);
        BigInteger q = rsa.genRandomPrime(512);
        BigInteger n = rsa.multiply(p, q);
        BigInteger phiN = rsa.phi(p, q);
        BigInteger pubKey = rsa.pubKey(phiN);
        BigInteger privKey = rsa.privKey(pubKey, phiN);
        System.out.println("Public Key: " + pubKey);
        System.out.println("Private Key: " + privKey);

        String plain = rsa.getInput2();
        //encrypt
        String message = "Rsa Security12";

        ArrayList<String> binaries = rsa.splitPlainText(plain, 1000);
        for (String block : binaries) {
            String encryption = rsa.encrypt(block, pubKey, n);
           //System.out.println("encryption " + encryption.length());

            //decrypt
            String decryption = rsa.decrypt(encryption, privKey, n);
           //System.out.println("decryption " + decryption.length());

            if (!decryption.equals(block)) {

                System.out.println("nomatch");
            }
        }
        //System.out.println("Cipher: " + decryption);
        //System.out.println("Decrypted Message: " + new String(new BigInteger(decryption, 2).toByteArray()));
    }

    BigInteger genRandomPrime(int length) {
        BigInteger k;
        k = BigInteger.probablePrime(length, new Random());

        return k;
    }

    String getBinary(BigInteger decimal) {
        String binary = decimal.toString(2);
        return binary;
    }

    BigInteger multiply(BigInteger p, BigInteger q) {
        return p.multiply(q);
    }

    BigInteger phi(BigInteger p, BigInteger q) {
        p = p.subtract(one());
        q = q.subtract(one());
        return p.multiply(q);
    }

    int randomWithRange(int min, int max) {
        int range = (max - min) + 1;
        return (int) (Math.random() * range) + min;
    }

    //comes in minus 1
    BigInteger pubKey(BigInteger phiN) {
        int phiLength = getBinary(phiN.subtract(one())).length();    //length of phi
        BigInteger gcd = BigInteger.valueOf(0);
        BigInteger e = null;
        while (gcd.equals(one()) == false) {
            //e = genRandomPrime(randomWithRange(2, phiLength));  //gen random prime between 1 and phi - 1
            e = BigInteger.valueOf(randomWithRange(2, phiLength));
            gcd = e.gcd(phiN);
        }

        return e;
    }

    BigInteger privKey(BigInteger e, BigInteger phiN) {
        return e.modInverse(phiN);  // d * e = 1 mod phiN
    }

    String encrypt(String mess, BigInteger e, BigInteger n) {
        //String binary = new BigInteger(mess.getBytes()).toString(2);
        //System.out.println(mess);
        BigInteger messDec = new BigInteger(mess, 2);
        return messDec.modPow(e, n).toString(2);
    }

    String decrypt(String cipher, BigInteger d, BigInteger n) {
        BigInteger cipherDec = new BigInteger(cipher, 2);
        return cipherDec.modPow(d, n).toString(2);
    }

    BigInteger one() {
        return BigInteger.valueOf(1);
    }

    String getInput() throws IOException {
        Path path = Paths.get("ana.jpg");
        byte[] fileContents = Files.readAllBytes(path);
        System.out.println("length " + fileContents.length);

        StringBuilder sB = new StringBuilder("");
        for (byte fC : fileContents) {
            String s1 = String.format("%8s", Integer.toBinaryString(fC & 0xFF)).replace(' ', '0');
            sB.append(s1);
        }
        //System.out.println(sB.toString());

        return sB.toString();
    }

    String getInput2() {
        StringBuilder s = new StringBuilder("");

        for (int i = 0; i < 1200000; i++) {
            s.append("1");
        }
        return s.toString();
    }

    ArrayList<String> splitPlainText(String plainBinary, int blockSize) {
        //startm marker/end marker
        int start = 0, end = 0;

        String block = null;
        ArrayList<String> blocks = new ArrayList();

        //break plain binary text into blocks
        while (end < plainBinary.length()) {
            end = start + blockSize;
            try {
                block = plainBinary.substring(start, end);

            } catch (IndexOutOfBoundsException error) {
                block = plainBinary.substring(start, plainBinary.length());

            }
            //split 128 block into 16 eight bit segments - String[0]...String[15]
            //add 128 bit segmented String[]'s to ArrayList
            blocks.add(block);
            start = end;
        }
        return blocks;
    }
}
