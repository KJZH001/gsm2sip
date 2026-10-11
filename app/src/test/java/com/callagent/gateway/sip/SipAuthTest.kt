package com.callagent.gateway.sip

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SipAuthTest {
    @Test
    fun parsesAsteriskPjsipChallenge() {
        val challenge = parse(
            "Digest realm=\"asterisk\",nonce=\"1791711311/ff401122fd6cd1ea4c96d5e24d7b5159\"," +
                "opaque=\"1211d3044c469b3c\",algorithm=MD5,qop=\"auth\""
        )

        assertEquals("asterisk", challenge.realm)
        assertEquals("1791711311/ff401122fd6cd1ea4c96d5e24d7b5159", challenge.nonce)
        assertEquals("1211d3044c469b3c", challenge.opaque)
        assertEquals("MD5", challenge.algorithm)
        assertEquals("auth", challenge.qop)
    }

    @Test
    fun acceptsParametersWithAndWithoutWhitespaceAndInAnyOrder() {
        val noSpaces = parse("Digest realm=\"x\",nonce=\"y\",opaque=\"z\"")
        val withSpaces = parse("Digest qop=\"auth\", opaque=\"z\", nonce=\"y\", realm=\"x\"")

        assertEquals("x", noSpaces.realm)
        assertEquals("y", noSpaces.nonce)
        assertEquals("z", noSpaces.opaque)
        assertEquals("x", withSpaces.realm)
        assertEquals("y", withSpaces.nonce)
        assertEquals("z", withSpaces.opaque)
        assertEquals("auth", withSpaces.qop)
    }

    @Test
    fun calculatesRfcDigestQopAuthResponse() {
        val params = SipAuth.AuthParams(
            realm = "testrealm@host.com",
            nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            opaque = "5ccc069c403ebaf9f0171e9517f40e41",
            qop = "auth"
        )
        val header = SipAuth.buildAuthHeader(
            method = "GET",
            uri = "/dir/index.html",
            username = "Mufasa",
            password = "Circle Of Life",
            params = params,
            cnonce = "0a4f113b",
            nonceCount = "00000001"
        )

        assertTrue(header.contains("response=\"6629fae49393a05397450978507c4ef1\""))
    }

    @Test
    fun authorizationIncludesEveryChallengeAndQopField() {
        val challenge = parse(
            "Digest realm=\"realm\", nonce=\"nonce\", opaque=\"opaque\", algorithm=MD5, qop=\"auth\""
        )
        val header = SipAuth.buildAuthHeader(
            "REGISTER", "sip:pbx.example:5060", "alice", "secret", challenge,
            cnonce = "fixed-cnonce", nonceCount = "00000001"
        )

        listOf(
            "username=\"alice\"", "realm=\"realm\"", "nonce=\"nonce\"",
            "uri=\"sip:pbx.example:5060\"", "response=\"", "algorithm=MD5",
            "qop=auth", "nc=00000001", "cnonce=\"fixed-cnonce\"", "opaque=\"opaque\""
        ).forEach { assertTrue("Missing $it from Authorization", header.contains(it)) }
    }

    @Test
    fun authenticatedRegisterUsesSameCallIdAndNextCseq() {
        val auth = SipAuth.buildAuthHeader(
            "REGISTER", "sip:pbx.example:5060", "alice", "secret",
            SipAuth.AuthParams("realm", "nonce", null, "auth"),
            cnonce = "cnonce"
        )
        val initial = SipBuilder.register("alice", "pbx.example", 5060, "192.0.2.10", 5060, "call-id", 7)
        val retry = SipBuilder.register("alice", "pbx.example", 5060, "192.0.2.10", 5060, "call-id", 8, auth)

        assertTrue(initial.contains("Call-ID: call-id\r\n"))
        assertTrue(retry.contains("Call-ID: call-id\r\n"))
        assertTrue(retry.contains("CSeq: 8 REGISTER\r\n"))
        assertTrue(retry.contains("Authorization: Digest"))
    }

    private fun parse(value: String): SipAuth.AuthParams {
        val message = SipMessage.parse(
            "SIP/2.0 401 Unauthorized\r\n" +
                "CSeq: 1 REGISTER\r\n" +
                "WWW-Authenticate: $value\r\n" +
                "Content-Length: 0\r\n\r\n"
        )
        assertNotNull(message)
        return requireNotNull(SipAuth.parseChallenge(message!!))
    }
}
