package peergos.shared.io.ipfs.multibase;

import peergos.shared.util.*;

public class Base16 {
    public static byte[] decode(String hex)
    {
        if(hex.length() % 2 != 0)
            throw new IllegalArgumentException("A base16 string must have an even number of symbols");
        byte[] res = new byte[hex.length()/2];
        for (int i=0; i < res.length; i++)
            res[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return res;
    }

    public static String encode(byte[] data)
    {
        return ArrayOps.bytesToHex(data);
    }
}
