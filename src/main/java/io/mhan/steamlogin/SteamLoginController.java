package io.mhan.steamlogin;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.Objects;

@Controller
public class SteamLoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/login/check")
    @ResponseBody
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
            @RequestParam(value = "openid.sig") String openidSig
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
        return String.valueOf(isTrue);
    }
}
