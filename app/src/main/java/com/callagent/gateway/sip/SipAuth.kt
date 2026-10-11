package com.callagent.gateway.sip

import java.security.MessageDigest
import java.security.SecureRandom

/** SIP Digest authentication (RFC 2617 / RFC 7616 MD5 compatibility). */
object SipAuth {
    private val random = SecureRandom()

    /** Parse Digest challenge parameters, allowing quoted commas and arbitrary parameter order. */
    fun parseChallenge(msg: SipMessage): AuthParams? {
        val authHeader = msg.header("www-authenticate") ?: msg.header("proxy-authenticate")
            ?: return null
        val schemeEnd = authHeader.indexOfFirst { it.isWhitespace() }
        if (schemeEnd < 0 || !authHeader.substring(0, schemeEnd).equals("Digest", ignoreCase = true)) {
            return null
        }
        val params = parseParameters(authHeader.substring(schemeEnd + 1))
        val realm = params["realm"] ?: return null
        val nonce = params["nonce"] ?: return null
        val algorithm = params["algorithm"] ?: "MD5"
        if (!algorithm.equals("MD5", ignoreCase = true)) return null
        val qopOptions = params["qop"]?.split(',')?.map { it.trim() }
        val qop = qopOptions?.firstOrNull { it.equals("auth", ignoreCase = true) }
        if (qopOptions != null && qop == null) return null
        return AuthParams(realm, nonce, params["opaque"], qop, algorithm.uppercase())
    }

    /** Build an Authorization header; optional fixed values make digest vectors reproducible in tests. */
    fun buildAuthHeader(
        method: String,
        uri: String,
        username: String,
        password: String,
        params: AuthParams,
        cnonce: String = randomCnonce(),
        nonceCount: String = "00000001"
    ): String {
        require(params.algorithm.equals("MD5", ignoreCase = true)) { "Unsupported digest algorithm" }
        val ha1 = md5("$username:${params.realm}:$password")
        val ha2 = md5("$method:$uri")
        val response = if (params.qop != null) {
            md5("$ha1:${params.nonce}:$nonceCount:$cnonce:${params.qop}:$ha2")
        } else {
            md5("$ha1:${params.nonce}:$ha2")
        }

        return buildString {
            append("Authorization: Digest username=\"$username\", ")
            append("realm=\"${params.realm}\", ")
            append("nonce=\"${params.nonce}\", ")
            append("uri=\"$uri\", ")
            append("response=\"$response\", ")
            append("algorithm=${params.algorithm}")
            if (params.qop != null) {
                append(", qop=${params.qop}, nc=$nonceCount, cnonce=\"$cnonce\"")
            }
            if (params.opaque != null) append(", opaque=\"${params.opaque}\"")
            append("\r\n")
        }
    }

    /** Build Authorization header for INVITE. */
    fun buildInviteAuthHeader(
        uri: String,
        username: String,
        password: String,
        params: AuthParams
    ): String = buildAuthHeader("INVITE", uri, username, password, params)

    private fun parseParameters(input: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        var start = 0
        var quoted = false
        var escaped = false
        for (i in input.indices) {
            val char = input[i]
            if (escaped) {
                escaped = false
            } else if (quoted && char == '\\') {
                escaped = true
            } else if (char == '"') {
                quoted = !quoted
            } else if (char == ',' && !quoted) {
                addParameter(input.substring(start, i), result)
                start = i + 1
            }
        }
        addParameter(input.substring(start), result)
        return result
    }

    private fun addParameter(raw: String, result: MutableMap<String, String>) {
        val eq = raw.indexOf('=')
        if (eq <= 0) return
        val key = raw.substring(0, eq).trim().lowercase()
        var value = raw.substring(eq + 1).trim()
        if (value.length >= 2 && value.first() == '"' && value.last() == '"') {
            value = value.substring(1, value.length - 1).replace("\\\"", "\"").replace("\\\\", "\\")
        }
        result[key] = value
    }

    private fun randomCnonce(): String = ByteArray(16).also(random::nextBytes)
        .joinToString("") { "%02x".format(it) }

    private fun md5(input: String): String {
        val digest = MessageDigest.getInstance("MD5")
        return digest.digest(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    data class AuthParams(
        val realm: String,
        val nonce: String,
        val opaque: String?,
        val qop: String?,
        val algorithm: String = "MD5"
    )
}
