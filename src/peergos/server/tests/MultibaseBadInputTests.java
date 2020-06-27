package peergos.server.tests;

import peergos.shared.io.ipfs.multibase.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class MultibaseBadInputTests {

    private String encoded;

    public MultibaseBadInputTests(String encoded) {
        this.encoded = encoded;
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(
                // Incorrect length
                new Object[]{"f12345"},
                //new Object[]{"bagqzlmnrxsa53pojwgi"},
                // Illegal characters
                new Object[]{"f0g"}
                //new Object[]{"bagqzlmnrxsa50pojwgia"}
                );
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecode() {
        Multibase.decode(encoded);
    }

}

