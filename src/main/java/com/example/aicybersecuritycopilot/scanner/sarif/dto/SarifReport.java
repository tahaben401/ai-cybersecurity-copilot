package com.example.aicybersecuritycopilot.scanner.sarif.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SarifReport {

    @JsonProperty("$schema")
    private String schema;
    private String version;
    private List<SarifRun> runs;

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifRun {
        private SarifTool tool;
        private List<SarifResult> results;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifTool {
        private SarifDriver driver;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifDriver {
        private String name;
        private String semanticVersion;
        private List<SarifRule> rules;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifRule {
        private String id;
        private String name;
        private SarifMultiformatMessage shortDescription;
        private SarifMultiformatMessage fullDescription;
        private SarifMultiformatMessage help;
        private Map<String, Object> properties;

        public String getImpact() {
            if (properties == null) return null;
            Object impact = properties.get("impact");
            return impact != null ? impact.toString() : null;
        }

        @SuppressWarnings("unchecked")
        public List<String> getTags() {
            if (properties == null) return List.of();
            Object tags = properties.get("tags");
            if (tags instanceof List<?>) {
                return (List<String>) tags;
            }
            return List.of();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifResult {
        private String ruleId;
        private String level;
        private SarifMessage message;
        private List<SarifLocation> locations;
        private Map<String, Object> properties;
        private List<SarifFix> fixes;

        public String getFingerprint() {
            if (properties == null) return null;
            Object fp = properties.get("fingerprint");
            return fp != null ? fp.toString() : null;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifMessage {
        private String text;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifMultiformatMessage {
        private String text;
        private String markdown;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifLocation {
        private SarifPhysicalLocation physicalLocation;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifPhysicalLocation {
        private SarifArtifactLocation artifactLocation;
        private SarifRegion region;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifArtifactLocation {
        private String uri;
        private int uriBaseId;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifRegion {
        private int startLine;
        private int startColumn;
        private int endLine;
        private int endColumn;
        private SarifSnippet snippet;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifSnippet {
        private String text;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifFix {
        private SarifMessage description;
        private List<SarifArtifactChange> artifactChanges;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifArtifactChange {
        private SarifArtifactLocation artifactLocation;
        private List<SarifReplacement> replacements;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifReplacement {
        private SarifRegion deletedRegion;
        private SarifArtifactContent insertedContent;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class SarifArtifactContent {
        private String text;
    }
}
