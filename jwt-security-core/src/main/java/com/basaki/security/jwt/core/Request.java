package com.basaki.security.jwt.core;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Created by indra.basak on 3/18/17.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Request implements Message {

    private String method;

    private String path;

    private String query;

    private byte[] body;
}
