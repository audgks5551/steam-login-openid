package io.mhan.steamlogin;

import io.mhan.steamlogin.security.SecurityUser;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@Controller
public class SteamLoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/login/check")
    public String check(
            @RequestParam(value = "openid.ns") String openidNs,
            @RequestParam(value = "openid.mode") String openidMode,
            @RequestParam(value = "openid.op_endpoint") String openidOpEndpoint,
            @RequestParam(value = "openid.claimed_id") String openidClaimedId,
            @RequestParam(value = "openid.identity") String openidIdentity,
            @RequestParam(value = "openid.return_to") String openidReturnTo,
            @RequestParam(value = "openid.response_nonce") String openidResponseNonce,
            @RequestParam(value = "openid.assoc_handle") String openidAssocHandle,
            @RequestParam(value = "openid.signed") String openidSigned,
            @RequestParam(value = "openid.sig") String openidSig,
            HttpSession session
    ) {

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString("https://steamcommunity.com/openid/login")
                .queryParam("openid.ns", openidNs)
                .queryParam("openid.mode", "check_authentication")
                .queryParam("openid.op_endpoint", openidOpEndpoint)
                .queryParam("openid.claimed_id", openidClaimedId)
                .queryParam("openid.identity", openidIdentity)
                .queryParam("openid.return_to", openidReturnTo)
                .queryParam("openid.response_nonce", openidResponseNonce)
                .queryParam("openid.assoc_handle", openidAssocHandle)
                .queryParam("openid.signed", openidSigned)
                .queryParam("openid.sig", openidSig);



        String block = WebClient.create("https://steamcommunity.com")
                .get()
                .uri(uriBuilder -> uriBuilder
                        .path("/openid/login")
                        .queryParam("openid.ns", openidNs)
                        .queryParam("openid.mode", "check_authentication")
                        .queryParam("openid.op_endpoint", openidOpEndpoint)
                        .queryParam("openid.claimed_id", openidClaimedId)
                        .queryParam("openid.identity", openidIdentity)
                        .queryParam("openid.return_to", openidReturnTo)
                        .queryParam("openid.response_nonce", openidResponseNonce)
                        .queryParam("openid.assoc_handle", openidAssocHandle)
                        .queryParam("openid.signed", openidSigned)
                        .queryParam("openid.sig", openidSig)
                        .build()
                )
                .retrieve()
                .bodyToMono(String.class)
                .block();
        System.out.println(block);

        boolean isTrue = Objects.requireNonNull(block).contains("true");

        // 1. findBySteamId(steamId)
        // 2. 없으면 회원가입 Member or 로그인
        // security 객체를 만들고 session에 저장


        Pattern pattern = Pattern.compile("\\d+");
        Matcher matcher = pattern.matcher(openidIdentity);
        String username;
        if (matcher.find()) {
            username = matcher.group();
        } else {
            throw new IllegalArgumentException();
        }

        // member저장

        SecurityUser user = SecurityUser.builder()
                .username("steam_" + username)
                .build();

        Authentication authentication =
                new OAuth2AuthenticationToken(user, user.getAuthorities(), "steam");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT"
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        return "redirect:/check";
    }

    @GetMapping("/check")
    @ResponseBody
    public String check() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        return user.getUsername();
    }
}
