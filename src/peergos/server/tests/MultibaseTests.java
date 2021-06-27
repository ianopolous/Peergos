package peergos.server.tests;

import peergos.shared.io.ipfs.multibase.*;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;

import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class MultibaseTests {

    private Multibase.Base base;
    private byte[] raw;
    private String encoded;

    public MultibaseTests(Multibase.Base base, byte[] raw, String encoded) {
        this.base = base;
        this.raw = raw;
        this.encoded = encoded;
    }

    @Parameters(name = "{index}: {0}, {2}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {Multibase.Base.Base58BTC, hexToBytes("1220120F6AF601D46E10B2D2E11ED71C55D25F3042C22501E41D1246E7A1E9D3D8EC"), "zQmPZ9gcCEpqKTo6aq61g2nXGUhM4iCL3ewB6LDXZCtioEB"},
                {Multibase.Base.Base58BTC, hexToBytes("1220BA8632EF1A07986B171B3C8FAF0F79B3EE01B6C30BBE15A13261AD6CB0D02E3A"), "zQmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy"},
                {Multibase.Base.Base58BTC, new byte[1], "z1"},
                {Multibase.Base.Base58BTC, new byte[2], "z11"},
                {Multibase.Base.Base58BTC, new byte[4], "z1111"},
                {Multibase.Base.Base58BTC, new byte[8], "z11111111"},
                {Multibase.Base.Base58BTC, new byte[16], "z1111111111111111"},
                {Multibase.Base.Base58BTC, new byte[32], "z11111111111111111111111111111111"},
                {Multibase.Base.Base16, hexToBytes("234ABED8DEBEDE"), "f234abed8debede"},
                {Multibase.Base.Base16, hexToBytes("87AD873DEFC2B288"), "f87ad873defc2b288"},
                {Multibase.Base.Base16, hexToBytes(""), "f"},
                {Multibase.Base.Base16, hexToBytes("01"), "f01"},
                {Multibase.Base.Base16, hexToBytes("0123456789ABCDEF"), "f0123456789abcdef"},
                {Multibase.Base.Base32, hexToBytes("01A195B1B1BC81DDBDC9B190"), "bagqzlmnrxsa53pojwgia"},
                {Multibase.Base.Base32, hexToBytes("017112207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069"), "bafyreid7qoywk77r7rj3slobqfekdvs57qwuwh5d2z3sqsw52iabe3mqne"},
                {Multibase.Base.Base32, asciiToBytes("Hello World!"), "bjbswy3dpeblw64tmmqqq"},
        });
    }

    @Test
    public void testEncode() {
        String output = Multibase.encode(base, raw);
        assertEquals(encoded, output);
    }

    @Test
    public void testDecode() {
        byte[] output = Multibase.decode(encoded);
        assertArrayEquals(String.format("Expected %s, but got %s", bytesToHex(raw), bytesToHex(output)), raw, output);
    }

    //Copied from https://stackoverflow.com/a/140861
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte[] asciiToBytes(String s) {
        return s.getBytes(US_ASCII);
    }

    //Copied from https://stackoverflow.com/a/9855338
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


}
