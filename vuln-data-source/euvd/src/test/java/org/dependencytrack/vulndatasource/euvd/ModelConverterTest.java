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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.cyclonedx.proto.v1_7.ScoreMethod;
import org.dependencytrack.vulndatasource.euvd.model.EuvdVulnerability;
import org.junit.jupiter.api.Test;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ModelConverterTest {
    private static final ObjectMapper JSON = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    @Test
    void shouldConvertVulnerabilityWithoutSoftwareMatchingData() throws Exception {
        final var data = JSON.readValue(getClass().getResourceAsStream("/advisory.json"), EuvdVulnerability.class);
        final var bom = ModelConverter.convert(data);
        final var vuln = bom.getVulnerabilities(0);
        assertThat(vuln.getSource().getName()).isEqualTo("EUVD");
        assertThat(vuln.getId()).isEqualTo("EUVD-2026-9999");
        assertThat(vuln.getReferencesList())
                .extracting(ref -> ref.getSource().getName())
                .containsExactly("NVD", "GITHUB");
        assertThat(vuln.getRatings(0).getMethod()).isEqualTo(ScoreMethod.SCORE_METHOD_CVSSV31);
        assertThat(vuln.getRatings(0).getScore()).isEqualTo(5.4);
        assertThat(vuln.getAffectsList()).isEmpty();
        assertThat(bom.getComponentsList()).isEmpty();
        assertThat(vuln.getDescription())
                .isEqualTo(requireNonNull(data.description()).strip());
        assertThat(bom.getExternalReferencesCount()).isEqualTo(2);
        assertThat(vuln.getPropertiesList())
                .extracting(property -> property.getName())
                .doesNotContain("dependency-track:euvd:raw");
        assertThat(vuln.getPublished().getSeconds())
                .isEqualTo(java.time.Instant.parse("2026-03-06T04:45:15Z").getEpochSecond());
        assertThat(ModelConverter.convert(data)).isEqualTo(bom);
    }

    @Test
    void shouldIgnoreLongProductNamesWithoutLosingVulnerabilityDetails() throws Exception {
        final var data =
                JSON.readValue(getClass().getResourceAsStream("/EUVD-2023-49907.json"), EuvdVulnerability.class);
        final var bom = ModelConverter.convert(data);
        assertThat(bom.getComponentsList()).isEmpty();
        assertThat(bom.getVulnerabilitiesCount()).isEqualTo(1);
        final var vuln = bom.getVulnerabilities(0);
        assertThat(vuln.getAffectsList()).isEmpty();
        assertThat(vuln.getId()).isEqualTo("EUVD-2023-49907");
        assertThat(vuln.getSource().getName()).isEqualTo("EUVD");
        assertThat(vuln.getDescription())
                .isEqualTo(requireNonNull(data.description()).strip());
        assertThat(vuln.getRatings(0).getScore()).isEqualTo(9.8);
        assertThat(vuln.getRatings(0).getMethod()).isEqualTo(ScoreMethod.SCORE_METHOD_CVSSV31);
        assertThat(vuln.getReferencesList())
                .extracting(ref -> ref.getId())
                .containsExactly("CVE-2023-45615", "GHSA-3p88-x42x-8hrq");
        assertThat(vuln.getPublished().getSeconds())
                .isEqualTo(java.time.Instant.parse("2023-11-14T22:44:59Z").getEpochSecond());
        assertThat(vuln.getUpdated().getSeconds())
                .isEqualTo(java.time.Instant.parse("2024-08-30T17:23:46Z").getEpochSecond());
        assertThat(bom.getExternalReferencesList())
                .extracting(ref -> ref.getUrl())
                .containsExactly("https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2023-017.txt");
    }

    @Test
    void shouldAllowMissingOptionalFields() throws Exception {
        final var advisory = JSON.readValue("{\"id\":\"EUVD-2026-1\"}", EuvdVulnerability.class);
        final var bom = ModelConverter.convert(advisory);
        assertThat(bom.getComponentsCount()).isZero();
        assertThat(bom.getVulnerabilities(0).getReferencesCount()).isZero();
    }

    @Test
    void shouldRejectInvalidScores() throws Exception {
        final var advisory = JSON.readValue("{\"id\":\"EUVD-2026-1\",\"baseScore\":11}", EuvdVulnerability.class);
        assertThatThrownBy(() -> ModelConverter.convert(advisory)).isInstanceOf(IllegalArgumentException.class);
    }
}
