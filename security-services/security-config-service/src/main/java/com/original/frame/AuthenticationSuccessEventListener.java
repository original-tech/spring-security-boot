package com.original.frame;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationSuccessEventListener implements ApplicationListener<AuthenticationSuccessEvent> {

    @Override
    public void onApplicationEvent(@NonNull AuthenticationSuccessEvent authenticationSuccessEvent) {
        log.info(authenticationSuccessEvent.toString());
        OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authenticationSuccessEvent.getSource();
        OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) oAuth2Authentication.getDetails();
        log.info(oAuth2AuthenticationDetails.getSessionId());
    }

}
