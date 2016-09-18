package com.b2s.sso.common.util;

import java.util.UUID;

public class IDService {

    public String generateID() {
        return UUID.randomUUID().toString();
    }

}
