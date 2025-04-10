package com.skygeo.security.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.skygeo.security.config.WeChatProperties;
import com.skygeo.security.dto.LoginResponse;
import com.skygeo.security.dto.WeChatBindingRequest;
import com.skygeo.security.dto.WeChatLoginRequest;
import com.skygeo.security.dto.WeChatSession;
import com.skygeo.security.entity.SecurityUser;
import com.skygeo.security.entity.WeChatUser;
import com.skygeo.security.repository.WeChatUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class WeChatAuthService {
    
    private final WeChatProperties weChatProperties;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final WeChatUserRepository weChatUserRepository;

    public LoginResponse authenticateWeChatUser(WeChatLoginRequest request) {
        try {
            WeChatSession session = getWeChatSession(request.getCode());
            
            // Check for WeChat API errors
            if (session.getErrcode() != null) {
                throw new AuthenticationCredentialsNotFoundException(
                    "WeChat authentication failed: " + session.getErrmsg()
                );
            }

            // Check if user is already bound
            Optional<WeChatUser> existingUser = weChatUserRepository.findByOpenId(session.getOpenId());
            
            if (existingUser.isPresent()) {
                SecurityUser securityUser = existingUser.get().getSecurityUser();
                String token = jwtService.generateTokenWithWeChatInfo(securityUser, existingUser.get());
                
                return LoginResponse.builder()
                    .token(token)
                    .tokenType("Bearer")
                    .username(securityUser.getUsername())
                    .weChatInfo(existingUser.get())
                    .build();
            }

            // If not bound, create temporary user
            SecurityUser tempUser = (SecurityUser) userDetailsService
                .loadUserByUsername("mini_program_" + session.getOpenId());
            String token = jwtService.generateToken(tempUser);

            return LoginResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .username(tempUser.getUsername())
                .needBinding(true)
                .build();

        } catch (Exception e) {
            throw new AuthenticationCredentialsNotFoundException(
                "WeChat authentication failed: " + e.getMessage()
            );
        }
    }

    public LoginResponse bindWeChatUser(WeChatBindingRequest request) {
        try {
            // First authenticate the system user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
                )
            );
            
            SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
            
            // Get WeChat session info
            WeChatSession session = getWeChatSession(request.getCode());
            
            if (session.getErrcode() != null) {
                throw new AuthenticationCredentialsNotFoundException(
                    "WeChat authentication failed: " + session.getErrmsg()
                );
            }
            
            // Check if already bound
            if (weChatUserRepository.findByOpenId(session.getOpenId()).isPresent()) {
                throw new AuthenticationCredentialsNotFoundException(
                    "WeChat account already bound to another user"
                );
            }
            
            // Create and save WeChat user
            WeChatUser weChatUser = WeChatUser.builder()
                .openId(session.getOpenId())
                .unionId(session.getUnionId())
                .sessionKey(session.getSessionKey())
                .nickname(request.getUserInfo().getNickName())
                .avatarUrl(request.getUserInfo().getAvatarUrl())
                .gender(request.getUserInfo().getGender())
                .country(request.getUserInfo().getCountry())
                .province(request.getUserInfo().getProvince())
                .city(request.getUserInfo().getCity())
                .language(request.getUserInfo().getLanguage())
                .securityUser(securityUser)
                .build();
            
            weChatUser = weChatUserRepository.save(weChatUser);
            
            String token = jwtService.generateTokenWithWeChatInfo(securityUser, weChatUser);
            
            return LoginResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .username(securityUser.getUsername())
                .weChatInfo(weChatUser)
                .build();
                
        } catch (Exception e) {
            throw new AuthenticationCredentialsNotFoundException(
                "WeChat binding failed: " + e.getMessage()
            );
        }
    }

    private WeChatSession getWeChatSession(String code) throws JsonMappingException, JsonProcessingException {
        String url = String.format(
            "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code",
            weChatProperties.getAppId(),
            weChatProperties.getAppSecret(),
            code
        );

        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
        JsonNode node = objectMapper.readTree(response.getBody());

        return WeChatSession.builder()
            .openId(node.get("openid").asText())
            .unionId(node.has("unionid") ? node.get("unionid").asText() : null)
            .sessionKey(node.get("session_key").asText())
            .errcode(node.has("errcode") ? node.get("errcode").asInt() : null)
            .errmsg(node.has("errmsg") ? node.get("errmsg").asText() : null)
            .build();
    }
}