package uk.ac.nottingham.cryptography;

import uk.ac.nottingham.cryptography.aes.AES128Encryptor;
import uk.ac.nottingham.cryptography.aes.AES128EncryptorImpl;
import uk.ac.nottingham.cryptography.galois.GF128Multiplier;
import uk.ac.nottingham.cryptography.galois.GF128MultiplierImpl;

import java.util.Arrays;

/**
 * Implementation of AEADCipher that encrypts using AES and calculates
 * a tag using GCM.
 * <p>
 * This class is the primary code file in which you can complete your
 * solution to the coursework.
 */
public class AESGCM implements AEADCipher {


    //TODO: Start with Encryption test.

    private final GF128Multiplier GF;
    private final AES128Encryptor encryptor;
    private byte[] key;
    private byte[] iv;
    private byte[] ivconcat;

    private byte[] e_k_intial;
    private byte[] e_k;
    private byte[] aad;
    private CipherMode mode;
    private int aadCounter;

    private int messageLen = 0;
    private int process_counter = 1;

    public AESGCM() {
        GF = new GF128MultiplierImpl();
        encryptor = new AES128EncryptorImpl();
        // Add your code here
    }



    @Override
    public void init(AEADParams params) {

        // Set all basic variables
        this.iv = params.getIv();
        this.key = params.getKey();
        this.encryptor.init(this.key);
        this.mode = params.getMode();
        this.GF.init(calculateH());
        this.aadCounter = 0;
        this.messageLen = 0;
        this.process_counter = 1;
        this.aad = new byte[16];
        this.e_k = new byte[16];
        this.e_k_intial = new byte[16];
        this.ivconcat = new byte[16];
        // Set all basic variables


        e_k        = generateKey(process_counter);
        e_k_intial = generateKey(process_counter);
        
        // 96 IV concatenated with 32 bit counter

        this.process_counter = 1; // Set counter to 1
    }



    @Override
    public void updateAAD(byte[] data) {

        for(int i = 0; i < data.length; i++){
            this.aad[i] ^= data[i];
        }

        GF.multiplyByH(this.aad);

        this.aadCounter += data.length * 8;

    }


    // after key gen


    @Override
    public void processBlock(byte[] data) {
        // Add your code here

        this.process_counter++;

        e_k = generateKey(process_counter);

        if(this.mode == CipherMode.ENCRYPT){
            // plaintext XOR with key to make it ciphertext
            for(int i = 0 ; i < data.length; i++){
                data[i] ^= e_k[i];
            }

            // XOR AAD with ciphertext
            for(int i = 0 ; i < data.length; i++){
                this.aad[i] ^= data[i];
            }

        }else if(this.mode == CipherMode.DECRYPT){

            for(int i = 0 ; i < data.length; i++){
                this.aad[i] ^= data[i];
            }
            for(int i = 0 ; i < data.length; i++){
                data[i] ^= e_k[i];
            }
        }

        // mult H
        GF.multiplyByH(this.aad);

        this.messageLen += data.length * 8;
    }

    @Override
    public void finalise(byte[] out) {
        // Add your code here

        //len(A) || len(C)
        byte[] A =  intToByteArray64(this.aadCounter);
        byte[] C =  intToByteArray64(this.messageLen);

        byte[] counterConcat = concatCounters(A,C);
        //len(A) || len(C)

        // (len(A) || len(C)) XOR multH
        for(int i = 0; i < counterConcat.length; i++){
            out[i] = (byte) (this.aad[i] ^ counterConcat[i]);
        }

        // (len(A) || len(C) XOR multH) MULT by H
        GF.multiplyByH(out);

        // ((len(A) || len(C) XOR multH) MULT by H) XOR initial key
        for(int i = 0; i < out.length ; i++){
            out[i] ^= e_k_intial[i];
        }

    }

    @Override
    public void verify(byte[] tag) throws InvalidTagException {
        finalise(this.aad);
        if(!(Arrays.equals(tag,this.aad))){throw new InvalidTagException();}
    }
    

    // HELPER FUNCTIONS
    byte[] concatCounters(byte[] A, byte[] C){
        byte[] counterConcat = new byte[16];

        for(int i = 0; i < A.length; i++){
            counterConcat[i] = A[i];
        }
        for(int i = 0; i < C.length; i++){
            counterConcat[A.length + i] = C[i];
        }
        return counterConcat;
    }

    public byte[] calculateH(){

        byte[] all_zeroes = new byte[16];
        byte[] write_to =  new byte[16];
        this.encryptor.encryptBlock(all_zeroes,write_to);
        return write_to;
    }


    public byte[] generateKey(int counter){

        byte[] _process_counter = intToByteArray(counter);
        byte[] key = new byte[16];

        // 96 IV concatenated with 32 bit counter
        for(int i = 0; i < iv.length; i++){
            ivconcat[i] = iv[i];
        }

        for(int i = 0; i <  _process_counter.length; i++){
            ivconcat[12+i] =  _process_counter[i];
        }
        // 96 IV concatenated with 32 bit counter

        this.encryptor.encryptBlock(ivconcat,key);

        return key;
    }

    private byte[] intToByteArray(int num){
        byte[] numBytes  = new byte[4];
        numBytes[0] = (byte) (num >> 24);
        numBytes[1] = (byte) (num >> 16);
        numBytes[2] = (byte) (num >> 8);
        numBytes[3] = (byte) (num);
        return numBytes;
    }

    private byte[] intToByteArray64(int num){
        byte[] numBytes  = new byte[8];

        numBytes[0] = (byte) ((long) num >> 56);
        numBytes[1] = (byte) ((long) num >> 48);
        numBytes[2] = (byte) ((long) num >> 40);
        numBytes[3] = (byte) ((long) num >> 32);
        numBytes[4] = (byte) ((long) num >> 24);
        numBytes[5] = (byte) ((long) num >> 16);
        numBytes[6] = (byte) ((long) num >> 8);
        numBytes[7] = (byte) ((long) num);
        return numBytes;

    }

    // HELPER FUNCTIONS

}
