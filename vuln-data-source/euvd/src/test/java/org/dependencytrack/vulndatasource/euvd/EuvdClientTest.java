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

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.dependencytrack.vulndatasource.euvd.model.EuvdVulnerabilitiesPage;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class EuvdClientTest {
    private EuvdClient client(WireMockRuntimeInfo info) {
        return new EuvdClient(
                HttpClient.newHttpClient(), info.getHttpBaseUrl(), OutboundConnectionPolicy.of(List.of("*")));
    }

    @Test
    void shouldHonorRetryAfterAndIgnoreUnknownFields(WireMockRuntimeInfo info) throws Exception {
        stubFor(get(urlPathEqualTo("/api/search"))
                .inScenario("retry")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "1"))
                .willSetStateTo("available"));
        stubFor(
                get(urlPathEqualTo("/api/search"))
                        .inScenario("retry")
                        .whenScenarioStateIs("available")
                        .willReturn(
                                okJson(
                                        "{\"items\":[{\"id\":\"EUVD-2026-1\",\"newField\":\"ignored\",\"epss\":0.1234567890123456789}],\"total\":1}")));
        final EuvdVulnerabilitiesPage result = client(info).search(null, LocalDate.parse("2026-03-06"), 0, 100);
        assertThat(result.items()).hasSize(1);
        assertThat(result.items().getFirst().id()).isEqualTo("EUVD-2026-1");
        assertThat(result.items().getFirst().epss()).isEqualByComparingTo("0.1234567890123456789");
        verify(2, getRequestedFor(urlPathEqualTo("/api/search")));
    }

    @Test
    void shouldDeserializePageAndConvertTypedVulnerability(WireMockRuntimeInfo info) throws Exception {
        final String advisory;
        try (final var input = requireNonNull(getClass().getResourceAsStream("/advisory.json"))) {
            advisory = new String(input.readAllBytes(), UTF_8);
        }
        stubFor(get(urlPathEqualTo("/api/search"))
                .willReturn(okJson("{\"items\":[" + advisory + "],\"total\":1,\"unknown\":true}")));
        final EuvdVulnerabilitiesPage result = client(info).search(null, LocalDate.parse("2026-03-06"), 0, 100);
        assertThat(result.total()).isEqualTo(1);
        final var vulnerability = result.items().getFirst();
        assertThat(vulnerability.datePublished()).isNotNull();
        assertThat(requireNonNull(vulnerability.datePublished()).toInstant())
                .isEqualTo(Instant.parse("2026-03-06T04:45:15Z"));
        assertThat(vulnerability.aliases()).containsExactly("CVE-2026-29061", "GHSA-q658-hfpg-35qc");
        assertThat(vulnerability.references()).hasSize(2);
        assertThat(vulnerability.epss()).isEqualByComparingTo("0.12");
        final var bom = ModelConverter.convert(vulnerability);
        assertThat(bom.getVulnerabilities(0).getId()).isEqualTo("EUVD-2026-9999");
        assertThat(bom.getVulnerabilities(0).getPublished().getSeconds())
                .isEqualTo(Instant.parse("2026-03-06T04:45:15Z").getEpochSecond());
        assertThat(bom.getComponentsList()).isEmpty();
        assertThat(bom.getVulnerabilities(0).getAffectsList()).isEmpty();
        assertThat(bom.getExternalReferencesCount()).isEqualTo(2);
    }

    @Test
    void shouldRejectPagesExceedingRequestedSize(WireMockRuntimeInfo info) {
        stubFor(get(urlPathEqualTo("/api/search"))
                .willReturn(okJson("{\"items\":[{\"id\":\"EUVD-2026-1\"},{\"id\":\"EUVD-2026-2\"}],\"total\":2}")));
        assertThatThrownBy(() -> client(info).search(null, LocalDate.parse("2026-03-06"), 0, 1))
                .isInstanceOf(java.io.IOException.class)
                .hasMessage("EUVD response exceeds requested page size");
    }

    @Test
    void shouldFailOnNoContentAndMalformedResponses(WireMockRuntimeInfo info) {
        final var client = client(info);
        for (final String json : new String[] {
            "null",
            "{\"items\":[],\"total\":1.5}",
            "{\"items\":[],\"total\":2147483648}",
            "{\"items\":[]}",
            "{\"items\":[null],\"total\":1}",
            "{\"items\":[{}],\"total\":1}",
            "{\"items\":[{\"id\":\"EUVD-2026-1\",\"dateUpdated\":\"bad date\"}],\"total\":1}",
            "{\"items\":null,\"total\":0}",
            "{\"items\":[],\"total\":-1}",
            "{\"items\":[{\"id\":\"bad\"}],\"total\":1}"
        }) {
            stubFor(get(urlPathEqualTo("/api/search")).willReturn(okJson(json)));
            assertThatThrownBy(() -> client.search(null, LocalDate.parse("2026-03-06"), 0, 100))
                    .isInstanceOf(java.io.IOException.class);
        }
        stubFor(get(urlPathEqualTo("/api/search")).willReturn(aResponse().withStatus(204)));
        assertThatThrownBy(() -> client.search(null, LocalDate.parse("2026-03-06"), 0, 100))
                .isInstanceOf(java.io.IOException.class);
    }

    @Test
    void shouldEnforceOutboundPolicy(WireMockRuntimeInfo info) {
        final var client = new EuvdClient(
                HttpClient.newHttpClient(), info.getHttpBaseUrl(), OutboundConnectionPolicy.of(List.of("external")));
        assertThatThrownBy(() -> client.search(null, LocalDate.parse("2026-03-06"), 0, 100))
                .isInstanceOf(org.dependencytrack.support.net.OutboundConnectionDeniedException.class);
        verify(0, getRequestedFor(urlPathEqualTo("/api/search")));
    }
}
