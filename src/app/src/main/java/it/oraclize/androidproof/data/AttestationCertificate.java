package it.oraclize.androidproof.data;

import java.io.Serializable;


public class AttestationCertificate implements Serializable {
    public byte[] leaf;
    public byte[] intermediate;
    public byte[] root;

    public AttestationCertificate(byte[] _leaf, byte[] _intermediate, byte[] _root) {
        leaf = _leaf;
        intermediate = _intermediate;
        root = _root;

    }
}
