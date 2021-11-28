package com.demo;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

@RestController
public class JWKSCachingController {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(JWKSCachingController.class);
  @SuppressWarnings("rawtypes")
  private JWKSource keySource;

  @Value("${jwksUrl}")
  private String jwksUrl;
  
  @Value("${claimUrl}")
  private String claimUrl;

  @Value("${subscriber}")
  private String subscriber;
  
  String jsonWebToken = "dummyJWTToken";
  
  @SuppressWarnings({"rawtypes", "unchecked", "deprecation"})
  @GetMapping
  public String verifyToken() {
  
    LOGGER.debug("verifyToken Controller invoked....");
    String uname = null;

    if(null == keySource) // if this line is commented, it is to trace calls made to jwks url
      keySource=getKeySource();
    
    ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

    JWSAlgorithm algorithm = JWSAlgorithm.RS256;
    JWSKeySelector keySelector = new JWSVerificationKeySelector(algorithm, keySource);
    jwtProcessor.setJWSKeySelector(keySelector);
    SecurityContext ctx = null; // optional context parameter, not required here
    JWTClaimsSet claimsSet;
    LOGGER.info(String.format("JWT JWSKeySelector '%s'", keySelector.toString()));
    LOGGER.info(String.format("JWT keySource '%s'", keySource.toString()));
    try {
      claimsSet = jwtProcessor.process(jsonWebToken, ctx);
      if (null != claimsSet) {
        if (!StringUtils.isEmpty(claimsSet.toJSONObject().get(claimUrl))) {
          uname = claimsSet.toJSONObject().get(claimUrl).toString();
        } else if (!StringUtils.isEmpty(claimsSet.toJSONObject().get(subscriber))) {
          uname = claimsSet.toJSONObject().get(subscriber).toString();
        }
      }

    } catch (ParseException | BadJOSEException | JOSEException e) {
      LOGGER.info("Error in  JWT token ", e);
    }
    return uname;    
  }
  
  @SuppressWarnings("rawtypes")
  private JWKSource getKeySource()
  {
    LOGGER.info(String.format("jwks url from Application '%s'", jwksUrl));
    try {
      keySource = new RemoteJWKSet(new URL(jwksUrl), new DefaultResourceRetriever(0, 0));
    } catch (MalformedURLException e) {
      LOGGER.info("MalformedURLException in  JWT token ", e);
      return null;
    }
    return keySource;
  }
  

}
