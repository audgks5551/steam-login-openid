package io.mhan.steamlogin;

import io.mhan.steamlogin.security.SecurityUser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;

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
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String body = WebClient.create("https://steamcommunity.com")
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

        boolean isTrue = Objects.requireNonNull(body).contains("true");

//         1. findBySteamId(steamId)
//         2. 없으면 회원가입 Member or 로그인
//         security 객체를 만들고 session에 저장


        Pattern pattern = Pattern.compile("\\d+");
        Matcher matcher = pattern.matcher(openidIdentity);
        String username;
        if (matcher.find()) {
            username = matcher.group();
        } else {
            throw new IllegalArgumentException();
        }

        SecurityUser user = SecurityUser.builder()
                .username("steam_" + username)
                .build();

        Authentication authentication =
                new OAuth2AuthenticationToken(user, user.getAuthorities(), "steam");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // 새로운 세션 생성
        session = request.getSession(true);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());

        // 세션 ID를 쿠키에 설정
        Cookie cookie = new Cookie("JSESSIONID", session.getId());
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        return "redirect:/check";
    }

    @GetMapping("/check")
    @ResponseBody
    public String check() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        return user.getUsername();
    }

    @GetMapping("/session")
    @ResponseBody
    public String session(HttpSession httpSession) {
        return httpSession.getId();
    }
}
