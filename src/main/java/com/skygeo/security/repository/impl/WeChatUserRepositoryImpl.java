package com.skygeo.security.repository.impl;

import com.skygeo.security.entity.WeChatUser;
import com.skygeo.security.repository.WeChatUserRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Repository("weChatUserRepository")
public class WeChatUserRepositoryImpl implements WeChatUserRepository {
    
    private final Map<String, WeChatUser> userMap = new ConcurrentHashMap<>();

    @Override
    public Optional<WeChatUser> findByOpenId(String openId) {
        return Optional.ofNullable(userMap.get(openId));
    }

    @Override
    public WeChatUser save(WeChatUser weChatUser) {
        userMap.put(weChatUser.getOpenId(), weChatUser);
        return weChatUser;
    }
}