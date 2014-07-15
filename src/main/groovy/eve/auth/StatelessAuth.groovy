package eve.auth

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.InvalidKeyException
import javax.crypto.SecretKey
import groovy.json.JsonBuilder
import groovy.json.JsonSlurper

/*
 * Sample:
 * def data = [id:'1', user:'palba', expirationDate:'01/01/2015']
 *
 * def s = new StatelessAuth("secret")
 * def token = s.generateToken(data)
 *
 * println "token $token"
 *
 * println s.validateToken(token)
 */

class StatelessAuth {
    String secret

    public StatelessAuth(String secret) {
        this.secret = secret
    }

    String hmac_sha256(String secretKey, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256")
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256")
            mac.init(secretKeySpec)
            byte[] digest = mac.doFinal(data.getBytes())
            return digest.encodeBase64().toString()
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key exception while converting to HMac SHA256")
        }
    }

    String generateToken(Map data) {
        def jsonString = new JsonBuilder(data).toString()
        def hash = hmac_sha256(secret, jsonString)
        def extendedData = jsonString+"_"+hash
        return (extendedData as String).getBytes().encodeBase64()
    }

    Map validateToken(String token) {
        try {
            String data = new String((token.decodeBase64()))
            def split = data.split("_")
            def slurper = new JsonSlurper()
            def json = slurper.parseText(split[0])
            def hash1 = split[1]
            def hash2 = hmac_sha256(secret, split[0])

            if (hash1 == hash2) {
                return slurper.parseText(split[0])
            }
        } catch (Exception e){
            //do nothing
            //e.printStackTrace()
        }
        return [:]
    }
}