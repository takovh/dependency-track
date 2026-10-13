/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.vulndatasource.euvd;

import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.ExternalReference;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.cyclonedx.proto.v1_7.VulnerabilityRating;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.vulndatasource.euvd.model.EuvdVulnerability;
import org.jspecify.annotations.Nullable;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

final class ModelConverter {
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("MMM d, yyyy, h:m:s a", Locale.US);

    private ModelConverter() {}

    static Bom convert(EuvdVulnerability advisory) {
        final var vuln = Vulnerability.newBuilder()
                .setId(advisory.id())
                .setSource(Source.newBuilder().setName("EUVD"));
        final String description = text(advisory.description());
        if (description != null) {
            vuln.setDescription(description);
        }
        final var published = advisory.datePublished();
        if (published != null) {
            vuln.setPublished(Timestamps.fromMillis(published.toInstant().toEpochMilli()));
            addProperty(vuln, "datePublished", DATE.format(published));
        }
        final var updated = advisory.dateUpdated();
        if (updated != null) {
            vuln.setUpdated(Timestamps.fromMillis(updated.toInstant().toEpochMilli()));
            addProperty(vuln, "dateUpdated", DATE.format(updated));
        }
        addProperty(vuln, "assigner", text(advisory.assigner()));
        final var epss = advisory.epss();
        if (epss != null) {
            addProperty(vuln, "epss", epss.toString());
        }
        final var score = advisory.baseScore();
        if (score != null) {
            final double value = score;
            if (!Double.isFinite(value) || value < 0 || value > 10) {
                throw new IllegalArgumentException("Invalid EUVD CVSS score");
            }
            final String version = advisory.baseScoreVersion() == null ? "" : advisory.baseScoreVersion();
            final var rating = VulnerabilityRating.newBuilder()
                    .setScore(value)
                    .setMethod(
                            switch (version) {
                                case "2", "2.0" -> ScoreMethod.SCORE_METHOD_CVSSV2;
                                case "3", "3.0" -> ScoreMethod.SCORE_METHOD_CVSSV3;
                                case "3.1" -> ScoreMethod.SCORE_METHOD_CVSSV31;
                                case "4", "4.0" -> ScoreMethod.SCORE_METHOD_CVSSV4;
                                default -> ScoreMethod.SCORE_METHOD_OTHER;
                            });
            final String vector = text(advisory.baseScoreVector());
            if (vector != null) {
                rating.setVector(vector);
            }
            vuln.addRatings(rating);
        }
        orEmpty(advisory.aliases()).stream().map(String::strip).distinct().forEach(alias -> {
            final String source = alias.matches("CVE-\\d{4}-\\d{4,}")
                    ? "NVD"
                    : alias.matches(
                                    "GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}")
                            ? "GITHUB"
                            : null;
            if (source != null) {
                vuln.addReferences(VulnerabilityReference.newBuilder()
                        .setId(alias)
                        .setSource(Source.newBuilder().setName(source)));
            }
        });
        final var bom = Bom.newBuilder().addVulnerabilities(vuln);
        orEmpty(advisory.references()).stream()
                .map(String::strip)
                .filter(url -> !url.isEmpty())
                .distinct()
                .forEach(url ->
                        bom.addExternalReferences(ExternalReference.newBuilder().setUrl(url)));
        return bom.build();
    }

    private static <T> List<T> orEmpty(@Nullable List<T> values) {
        return values == null ? List.of() : values;
    }

    private static void addProperty(Vulnerability.Builder vuln, String field, @Nullable String value) {
        if (value != null) {
            vuln.addProperties(Property.newBuilder()
                    .setName("dependency-track:vuln:" + field)
                    .setValue(value));
        }
    }

    private static @Nullable String text(@Nullable String value) {
        if (value == null) {
            return null;
        }
        final String stripped = value.strip();
        return stripped.isEmpty() ? null : stripped;
    }
}
