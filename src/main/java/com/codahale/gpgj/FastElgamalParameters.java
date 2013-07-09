package com.codahale.gpgj;

import org.bouncycastle.crypto.params.ElGamalParameters;

import static com.codahale.gpgj.FastDSAParameters.parse;

/**
 * Pre-generated Elgamal parameters. Generated with OpenSSL (openssl dhparam -text 2048).
 */
class FastElgamalParameters {
    private FastElgamalParameters() { /* singleton */ }

    /**
     * A pre-generated set of parameters for 1024-bit Elgamal keys.
     */
    static final ElGamalParameters ELGAMAL_1024 = new ElGamalParameters(
            parse(
                    "00:80:2c:be:1e:fc:d2:f0:61:54:6f:f3:70:4b:26:" +
                    "e1:da:88:c3:25:21:9c:1f:b5:44:69:2d:8b:76:92:" +
                    "80:70:55:a8:a5:fc:13:5b:46:a3:ad:02:02:36:95:" +
                    "1a:71:9c:71:d5:19:3b:25:cc:43:27:82:10:8a:13:" +
                    "b6:d9:4d:f6:34:99:df:b5:1b:85:b5:ad:89:ce:8f:" +
                    "cf:83:64:88:6c:4a:1b:90:0a:5d:54:1b:22:c6:b7:" +
                    "35:8f:0f:72:67:ec:99:b2:f5:54:2e:27:4a:23:ce:" +
                    "f9:88:8b:1e:21:10:3e:24:73:87:65:73:18:e4:2d:" +
                    "bf:9b:52:21:29:13:4e:14:db"
            ),
            parse(
                    "2"
            )
    );

    /**
     * A pre-generated set of parameters for 2048-bit Elgamal keys.
     */
    static final ElGamalParameters ELGAMAL_2048 = new ElGamalParameters(
            parse(
                    "00:bd:cf:78:c8:b2:6c:80:4a:8a:22:30:90:cb:14:" +
                    "72:2e:08:0a:1c:2a:ce:f2:e4:ab:b2:a7:4a:97:55:" +
                    "45:70:79:88:85:94:ef:a7:64:8c:3f:66:e2:ee:a7:" +
                    "f8:e3:ed:ea:4d:60:89:0b:b2:19:f7:3a:04:bd:d8:" +
                    "fc:ba:67:3a:cf:05:5e:25:b6:08:bf:7b:79:26:c2:" +
                    "64:5e:3b:36:05:4f:35:a6:1a:49:4c:a1:dc:63:89:" +
                    "49:57:e1:af:ca:7a:5e:00:5e:c7:b2:7d:f3:5b:44:" +
                    "d1:97:07:30:1e:0e:ea:eb:07:58:0d:b0:5d:95:f1:" +
                    "4d:a7:36:cf:49:4e:94:c3:50:db:b9:e6:18:5a:6a:" +
                    "48:33:fc:19:aa:4a:4a:d2:aa:d8:86:36:0a:93:dc:" +
                    "29:09:b8:fa:a4:3d:89:37:e5:82:56:7c:fb:ad:60:" +
                    "74:b2:c5:e0:66:b2:e8:c7:b0:ec:fb:3c:cc:9c:6e:" +
                    "b4:0a:13:b1:18:4e:f9:dc:55:32:9b:c1:30:55:fb:" +
                    "02:74:39:15:4e:e9:31:7d:27:f4:39:90:4f:36:be:" +
                    "f6:83:a4:b4:05:f0:10:f0:2e:62:54:4d:18:fb:13:" +
                    "de:e6:99:7a:21:55:1c:0b:61:6c:58:4f:e2:da:ab:" +
                    "67:89:86:1e:12:24:88:dd:4b:63:38:4e:74:53:ca:" +
                    "35:db"
            ),
            parse(
                    "2"
            ));

    /**
     * A pre-generated set of parameters for 4096-bit Elgamal keys.
     */
    static final ElGamalParameters ELGAMAL_4096 = new ElGamalParameters(
            parse(
                    "00:be:e9:8d:72:25:5c:76:e4:17:4a:71:58:a8:c9:" +
                    "c2:13:c3:45:18:2c:bd:17:c1:c0:9e:94:35:60:53:" +
                    "ec:61:e1:df:7e:02:53:46:59:9e:28:c2:dd:32:7e:" +
                    "77:ed:84:91:d5:08:bc:f8:6f:df:86:b8:66:1f:1d:" +
                    "63:7f:78:63:ec:51:ad:e9:a1:cb:b2:69:14:f2:14:" +
                    "ad:54:b0:df:16:c3:fe:5f:0c:c1:05:cf:50:13:38:" +
                    "ec:3a:90:c3:fd:b7:58:ef:79:a9:b4:b1:d5:61:d6:" +
                    "58:99:f0:7d:49:e7:9c:43:cb:2d:78:97:92:00:5c:" +
                    "58:82:40:b4:9a:f9:8a:24:a2:06:98:76:12:14:6e:" +
                    "91:e1:8f:8f:43:b9:d0:ad:da:be:06:ae:06:88:93:" +
                    "ff:65:b3:c0:cf:18:70:b7:43:ea:c1:6f:02:d7:20:" +
                    "a3:80:1f:fa:36:bc:2f:b4:26:98:92:ab:91:61:76:" +
                    "1b:77:6a:f6:01:5a:82:82:c7:93:e9:27:1b:74:20:" +
                    "5c:c0:38:f5:d0:2b:66:1a:42:97:89:6f:72:9a:21:" +
                    "fd:30:60:dc:48:c1:c3:d5:2e:5d:18:a2:f4:73:4f:" +
                    "16:cc:37:56:22:79:0e:76:c9:a0:70:4f:d4:be:9e:" +
                    "08:99:d5:1c:16:57:d4:c9:0b:3c:8a:e0:ad:f7:91:" +
                    "04:bb:f6:7c:3b:f1:f4:7b:63:34:3a:e5:f0:ad:ef:" +
                    "19:0e:ff:54:69:d8:07:61:e5:03:64:55:93:3d:be:" +
                    "b0:46:66:e2:93:3c:70:d2:62:4a:d8:3f:30:eb:05:" +
                    "18:14:cc:10:e8:1f:d2:b7:54:2d:2b:54:80:c2:f7:" +
                    "8b:1c:36:2d:7f:60:80:80:cc:89:6d:a4:a0:f5:4f:" +
                    "dc:52:af:a0:f0:a2:77:a0:d6:9a:5c:db:11:72:4f:" +
                    "ac:32:ce:35:86:50:dd:87:0c:85:f4:5c:79:3d:d9:" +
                    "2a:98:d2:cb:5d:db:5f:db:7f:d3:c0:2c:d6:9a:9b:" +
                    "a9:44:37:0c:7a:7a:29:0f:d7:71:02:16:82:87:43:" +
                    "c9:c4:e5:96:61:14:c2:9d:4a:fa:f3:3a:c2:47:37:" +
                    "40:74:ff:71:b2:d1:f7:0b:bd:6d:28:a1:37:21:6e:" +
                    "60:25:f7:9d:42:23:d9:72:2d:ed:f5:37:88:9e:50:" +
                    "b4:01:b2:12:04:e7:dc:99:45:80:fa:2e:1b:d3:f0:" +
                    "66:86:58:5f:b3:75:c3:6c:fe:88:50:38:5a:5c:31:" +
                    "aa:08:69:d4:21:5d:2a:e0:a8:98:ca:4e:a3:aa:c0:" +
                    "c3:7c:4c:87:b0:a8:04:dc:9d:35:39:7c:ed:19:e2:" +
                    "cb:29:45:fc:4d:58:de:47:30:db:81:ce:b3:9a:41:" +
                    "cd:62:d3"
            ),
            parse(
                    "2"
            )
    );
}
