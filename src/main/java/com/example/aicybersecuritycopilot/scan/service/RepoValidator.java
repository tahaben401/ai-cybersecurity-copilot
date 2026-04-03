package com.example.aicybersecuritycopilot.scan.service;

import org.springframework.stereotype.Service;
import java.util.regex.Pattern;

@Service
public class RepoValidator {

    
    private static final Pattern GITHUB_URL_PATTERN = Pattern.compile("^https://github\\.com/[A-Za-z0-9-]+/[A-Za-z0-9-_.]+$");
    
    
    private static final Pattern DANGEROUS_CHARS_PATTERN = Pattern.compile("[;&|`$><\\\\]");

    public boolean isValidGithubUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }

        
        if (DANGEROUS_CHARS_PATTERN.matcher(url).find()) {
            return false;
        }

        if (!GITHUB_URL_PATTERN.matcher(url).matches()) {
            return false;
        }

        return true;
    }
}
