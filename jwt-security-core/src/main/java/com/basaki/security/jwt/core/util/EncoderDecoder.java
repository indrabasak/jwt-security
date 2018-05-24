package com.basaki.security.jwt.core.util;

import java.net.URLEncoder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

/**
 * Created by indra.basak on 3/21/17.
 */
@Slf4j
public class EncoderDecoder {

    public static String encode(String value) {
        try {
            String encoded =
                    StringUtils.isBlank(value) ? "" : URLEncoder.encode(value,
                            "UTF-8");
            return StringUtils.replace(encoded, "*", "%2A");
        } catch (Exception e) {
            log.error("Failed to encode " + value , e);
            return "";
        }
    }
}
