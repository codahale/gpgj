package com.codahale.gpgj;

import org.bouncycastle.crypto.params.DSAParameters;

import java.math.BigInteger;

/**
 * Pre-generated DSA parameters. Generated with OpenSSL (openssl dsaparam -text 2048).
 */
class FastDSAParameters {
    private FastDSAParameters() { /* singleton */ }

    /**
     * A pre-generated set of parameters for 1024-bit DSA keys.
     */
    static final DSAParameters DSA_1024 = new DSAParameters(
            parse(
                    "00:e6:2a:de:78:90:1b:af:65:00:3a:a0:fb:f1:8b:" +
                    "60:1d:a0:b5:3a:6d:25:35:7e:94:a1:3f:e6:e5:82:" +
                    "0c:a3:43:18:2b:15:39:b0:38:95:3b:ca:ff:12:69:" +
                    "f4:90:bd:1a:f4:0d:a5:d0:08:6b:e3:33:61:a1:1c:" +
                    "ae:78:d3:46:5a:c2:70:a8:c9:50:5b:31:d4:50:17:" +
                    "d8:ef:9f:eb:83:0c:18:e6:f4:09:0e:c9:18:c1:e1:" +
                    "de:32:ac:85:e3:9a:c5:74:d0:73:bb:a3:0a:09:74:" +
                    "98:7a:8c:e1:ff:c8:ae:be:00:95:f5:a4:de:6a:52:" +
                    "e8:ec:c3:c9:9b:f9:bd:a0:2f"
            ),
            parse(
                    "00:e2:66:57:95:7f:45:2e:9f:d0:d6:79:92:af:c2:" +
                    "07:f8:f0:4a:ad:fb"
            ),
            parse(
                    "33:a6:a7:1f:12:49:e7:4a:1a:c3:b1:d6:82:cf:0b:" +
                    "1b:82:08:df:dd:ff:aa:bf:9e:1d:8f:ac:8f:27:bc:" +
                    "8f:a4:87:d1:5c:f3:15:1d:b9:c6:2d:8c:07:46:43:" +
                    "46:b6:76:a0:0a:be:cd:ee:7c:ef:e8:22:4f:52:60:" +
                    "85:5e:c5:0e:48:0c:b3:69:cc:db:12:43:b3:2e:5b:" +
                    "d3:78:e6:6b:1f:17:3d:69:09:b7:df:6b:bd:39:99:" +
                    "81:5d:a9:54:aa:70:e1:fb:ab:7d:c5:72:81:86:5f:" +
                    "f3:27:0d:93:56:f6:1f:f4:7a:0d:67:2c:ac:69:e6:" +
                    "e7:47:81:13:d0:44:49:28"
            ));

    /**
     * A pre-generated set of parameters for 2048-bit DSA keys.
     */
    static final DSAParameters DSA_2048 = new DSAParameters(
            parse(
                    "00:a6:ec:d8:eb:30:31:a0:ed:05:f9:5a:dd:b3:07:" +
                    "53:67:10:ee:9b:d4:05:fe:f6:61:58:10:05:dc:63:" +
                    "ab:90:49:ae:86:f9:0f:c6:4f:f5:7c:16:b0:35:34:" +
                    "82:bc:f4:e5:97:08:2e:d2:25:22:14:93:77:fe:a0:" +
                    "30:7f:0d:44:ce:8b:8c:22:6b:3f:b4:ab:87:c6:0a:" +
                    "11:56:60:6f:fc:6e:2b:02:0d:0d:a5:5a:dc:c6:7f:" +
                    "19:0d:5a:76:6e:15:c8:cf:b8:3d:80:7f:27:de:78:" +
                    "f3:fe:75:e2:c8:f6:7b:98:4e:a2:b1:ca:5b:cd:5d:" +
                    "24:1c:14:59:3b:4b:37:43:da:b7:09:06:46:1e:41:" +
                    "63:5d:91:bd:4e:71:26:35:ba:3f:4a:f5:eb:eb:0a:" +
                    "5b:b1:d6:17:a8:f5:63:6f:3b:34:29:83:43:95:fc:" +
                    "68:57:a3:e2:1e:4f:0f:18:5d:9f:75:0a:48:db:ac:" +
                    "36:1b:e1:c0:2d:22:c0:65:f9:45:a1:84:01:3e:4a:" +
                    "dd:c7:cd:e6:1c:e8:4e:9c:d8:14:1d:96:2e:70:cc:" +
                    "da:0a:5e:89:3a:fe:1a:54:2b:fa:d9:a1:27:f2:af:" +
                    "44:69:fe:66:cc:47:ca:88:20:e5:0c:6f:e0:8d:15:" +
                    "93:4a:d3:06:b6:6d:d8:7e:e9:71:e8:ad:a3:0b:d3:" +
                    "89:0b"
            ),
            parse(
                    "00:ef:e3:c0:f9:28:3d:4f:8e:3c:73:27:f7:ae:2c:" +
                    "df:34:09:e4:97:b4:c0:1f:31:05:2f:9a:97:df:04:" +
                    "2c:79:9d"
            ),
            parse(
                    "00:92:81:1c:f2:ce:dd:84:f9:ad:f6:f9:95:5d:f6:" +
                    "21:3e:d8:d5:b2:f3:48:52:86:21:3f:4a:f1:74:f4:" +
                    "88:80:05:52:12:33:6d:0e:8a:ee:54:60:c8:50:db:" +
                    "7e:20:96:34:1b:f5:56:0e:26:d4:13:45:14:2b:ff:" +
                    "92:78:d7:ef:8d:9e:e2:18:78:43:df:9f:1e:a2:2a:" +
                    "2b:8f:d6:e8:24:5f:57:64:bd:7d:ca:10:91:22:4c:" +
                    "de:04:c3:73:00:ad:a1:08:fa:a5:c0:93:93:bf:9b:" +
                    "da:c9:e4:c5:e6:7b:7a:7e:92:e2:79:ba:dd:3c:a0:" +
                    "d8:61:cb:af:b3:2e:00:b5:32:df:6f:d9:54:7c:87:" +
                    "26:2a:51:b8:e3:c9:b6:98:ed:a5:f0:c3:e1:e5:4f:" +
                    "01:ce:7f:ef:08:8e:7f:70:2a:15:5f:4f:2c:bf:0d:" +
                    "f3:d3:65:00:f0:bb:54:42:dd:6f:b5:6b:2a:7b:06:" +
                    "85:fd:d3:d3:aa:83:66:ef:0f:41:f2:e7:40:75:56:" +
                    "b7:e4:12:d7:71:93:10:75:87:35:d4:ab:1f:cc:fa:" +
                    "6c:ff:ec:37:48:f6:81:6d:78:59:20:da:64:93:15:" +
                    "2a:37:2d:29:1e:b8:44:63:9c:66:e9:3f:93:42:e5:" +
                    "ce:df:dc:9b:4d:f0:81:1a:b6:f4:48:41:da:1a:cd:" +
                    "50:a3"
            )
    );

    /**
     * A pre-generated set of parameters for 3072-bit DSA keys.
     */
    static final DSAParameters DSA_3072 = new DSAParameters(
            parse(
                    "00:bb:2f:37:ca:f3:34:98:d5:18:30:21:8f:aa:d8:" +
                    "10:39:db:9a:34:53:85:e1:6d:d7:9f:00:5f:15:24:" +
                    "c6:30:62:e9:d7:32:6c:37:44:38:a5:07:b3:b4:33:" +
                    "cb:52:7e:31:1c:5a:c9:52:fc:de:01:82:c7:1f:ac:" +
                    "82:8c:1e:15:a3:0d:95:ee:ec:a4:21:8b:13:b3:f1:" +
                    "7d:84:00:e8:f6:b6:19:22:ba:06:62:21:af:15:e5:" +
                    "fc:da:cc:21:4b:ef:c9:eb:5c:ff:6a:66:c4:5e:cd:" +
                    "0c:02:5f:1c:f0:4d:2c:51:46:67:9c:e9:90:2f:10:" +
                    "9a:d8:23:ff:1a:54:56:5f:75:3c:f3:9c:62:bf:83:" +
                    "7c:7b:8b:c1:d5:62:8a:3b:86:c4:1d:24:ed:ad:36:" +
                    "3a:f0:a0:79:75:c5:cc:c0:a8:23:46:89:99:94:c8:" +
                    "c9:4f:a0:22:fc:d1:93:66:74:d5:53:18:37:b7:88:" +
                    "9f:24:91:d1:d1:13:62:58:0f:9c:38:ac:8f:e7:04:" +
                    "f0:ff:7e:0f:8e:8f:92:98:42:d6:81:5f:fe:91:a8:" +
                    "36:3d:11:ef:02:02:84:75:65:b2:10:d2:a0:7e:38:" +
                    "ab:25:a0:bb:4d:c3:fd:9f:4b:ef:df:30:30:f5:c8:" +
                    "6c:b8:22:ca:7f:8d:ff:c4:ff:db:aa:4e:27:27:49:" +
                    "13:61:ba:45:e8:7c:17:e4:00:55:4a:83:84:b3:33:" +
                    "1b:e1:28:e0:03:ec:46:70:60:da:7a:35:6b:99:aa:" +
                    "57:0e:32:c9:e4:00:0d:78:6b:f4:2f:b8:e3:24:78:" +
                    "0e:2d:ad:2e:74:05:57:b1:60:41:29:7c:63:ee:8c:" +
                    "ef:5d:96:c0:81:2f:d7:d2:d0:21:32:37:88:1c:3f:" +
                    "4c:54:29:0d:4d:f7:f8:60:41:ae:08:9c:37:96:63:" +
                    "b3:2a:ab:96:89:58:85:8f:49:24:35:bc:ea:0d:db:" +
                    "cc:27:8c:b4:36:8a:14:26:2f:9c:7f:df:8f:05:eb:" +
                    "98:1f:0d:c7:9e:6c:d4:40:22:e5"
            ),
            parse(
                    "00:d8:86:ce:e1:89:70:82:71:e4:d4:60:a2:ef:c0:" +
                    "81:5d:be:22:30:67:17:99:cf:f0:49:b4:a9:d6:ee:" +
                    "be:be:85"
            ),
            parse(
                    "00:81:2b:85:a2:73:8b:5f:13:ef:38:26:c3:6c:dd:" +
                    "04:cd:ee:40:8a:34:c4:2f:88:f1:03:dc:30:aa:e7:" +
                    "d3:30:69:15:06:d9:04:bd:e6:9b:38:7c:27:24:66:" +
                    "ea:f7:04:e4:2f:05:b6:d5:ae:b3:e1:e8:71:e6:4c:" +
                    "f1:9d:9d:86:6a:1d:03:f7:d9:91:6c:70:ab:e7:75:" +
                    "37:cc:50:c1:68:33:24:bd:90:f4:4a:bb:bd:05:32:" +
                    "01:fc:d2:67:42:5b:8b:da:cd:5c:a8:8f:49:52:db:" +
                    "5c:d2:d2:62:b9:3f:c8:07:93:d8:51:2d:0e:61:16:" +
                    "d9:57:ee:2c:3a:f4:84:73:1b:43:e9:11:e8:c9:a9:" +
                    "8b:9d:61:0d:8b:9a:82:97:ef:45:a0:a1:f5:19:47:" +
                    "83:07:d9:13:3f:02:61:57:19:70:80:61:d6:ac:af:" +
                    "27:c7:d8:8a:0d:ac:66:c2:77:ce:64:9e:f2:2f:ea:" +
                    "74:0e:44:fe:6f:5c:71:91:a9:ea:9c:92:65:d0:a9:" +
                    "5f:03:18:c2:bd:81:f2:34:a8:fc:52:e9:0e:93:e0:" +
                    "e8:3d:2d:0f:79:dc:ad:2f:55:fc:e4:15:19:46:7a:" +
                    "4a:d7:4f:56:76:dd:f6:58:16:3d:df:4b:4a:e8:86:" +
                    "a3:76:2e:5b:28:c2:b3:0f:b8:f7:8b:90:20:15:d1:" +
                    "cf:08:c8:e1:34:dc:0d:ca:55:93:34:5c:9f:66:e7:" +
                    "59:0f:05:aa:75:56:44:79:56:bf:34:65:19:ca:33:" +
                    "db:85:ac:7a:5a:3d:89:28:e4:d9:53:ae:4c:c2:2e:" +
                    "7e:c6:94:4d:89:8d:7f:e3:14:b7:72:aa:ff:13:2e:" +
                    "4b:97:8e:a9:72:b6:52:9a:a0:de:58:45:3c:4d:1d:" +
                    "eb:d2:4a:be:d7:e4:bf:14:d6:5c:67:90:cf:a7:5b:" +
                    "1e:da:98:a0:80:52:00:a3:81:cc:45:b3:06:35:ca:" +
                    "2f:a3:4e:f3:4c:d5:ca:30:d1:54:36:62:29:3e:0d:" +
                    "cb:67:aa:2f:26:99:28:34:15:0b"
            )
    );

    static BigInteger parse(String value) {
        return new BigInteger(value.replaceAll("[^a-f0-9]", ""), 16);
    }
}
