package com.skygeo.security.repository;

import com.skygeo.security.entity.WeChatUser;
import java.util.Optional;

public interface WeChatUserRepository {
    Optional<WeChatUser> findByOpenId(String openId);
    WeChatUser save(WeChatUser weChatUser);
}