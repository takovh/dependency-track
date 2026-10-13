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
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.LocalDate;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class EuvdVulnDataSourceTest {
    private EuvdVulnDataSource source(WireMockRuntimeInfo info, MockKeyValueStore store, String end) {
        return new EuvdVulnDataSource(
                new EuvdClient(
                        HttpClient.newHttpClient(),
                        info.getHttpBaseUrl(),
                        OutboundConnectionPolicy.of(java.util.List.of("*"))),
                new WatermarkManager(store),
                LocalDate.parse(end));
    }

    @Test
    void shouldCoverUnboundedHistoryAndLeapMonthAndCommitEmptyRun(WireMockRuntimeInfo info) {
        stubFor(get(urlPathEqualTo("/api/search")).willReturn(okJson("{\"items\":[],\"total\":0}")));
        final var store = new MockKeyValueStore();
        try (final var source = source(info, store, "2000-03-06")) {
            assertThat(source.hasNext()).isFalse();
            assertThat(store.get("watermark").value()).isEqualTo("2000-03-06");
        }
        verify(getRequestedFor(urlPathEqualTo("/api/search"))
                .withQueryParam("toUpdatedDate", equalTo("1999-12-31"))
                .withQueryParam("fromUpdatedDate", absent()));
        verify(getRequestedFor(urlPathEqualTo("/api/search"))
                .withQueryParam("fromUpdatedDate", equalTo("2000-01-01"))
                .withQueryParam("toUpdatedDate", equalTo("2000-01-31")));
        verify(getRequestedFor(urlPathEqualTo("/api/search"))
                .withQueryParam("fromUpdatedDate", equalTo("2000-02-01"))
                .withQueryParam("toUpdatedDate", equalTo("2000-02-29")));
        verify(getRequestedFor(urlPathEqualTo("/api/search")).withQueryParam("toUpdatedDate", equalTo("2000-03-06")));
        assertThat(store.get("watermark").value()).isEqualTo("2000-03-06");
    }

    @Test
    void shouldQueryMonthlyWindowsWithExistingWatermark(WireMockRuntimeInfo info) {
        stubFor(get(urlPathEqualTo("/api/search")).willReturn(okJson("{\"items\":[],\"total\":0}")));
        final var store = new MockKeyValueStore();
        store.put("watermark", "2000-02-01");
        try (final var source = source(info, store, "2000-03-06")) {
            assertThat(source.hasNext()).isFalse();
            assertThat(store.get("watermark").value()).isEqualTo("2000-03-06");
        }
        verify(3, getRequestedFor(urlPathEqualTo("/api/search")));
        verify(getRequestedFor(urlPathEqualTo("/api/search"))
                .withQueryParam("fromUpdatedDate", equalTo("2000-01-31"))
                .withQueryParam("toUpdatedDate", equalTo("2000-01-31")));
        verify(getRequestedFor(urlPathEqualTo("/api/search"))
                .withQueryParam("fromUpdatedDate", equalTo("2000-02-01"))
                .withQueryParam("toUpdatedDate", equalTo("2000-02-29")));
        verify(getRequestedFor(urlPathEqualTo("/api/search"))
                .withQueryParam("fromUpdatedDate", equalTo("2000-03-01"))
                .withQueryParam("toUpdatedDate", equalTo("2000-03-06")));
    }

    @Test
    void shouldNotCommitWhenFinalBatchHasNotBeenAcknowledged(WireMockRuntimeInfo info) {
        pages();
        final var store = new MockKeyValueStore();
        store.put("watermark", "2026-03-05");
        try (final var source = source(info, store, "2026-03-06")) {
            final var bom = source.next();
            assertThat(source.hasNext()).isFalse();
            assertThat(bom.getVulnerabilities(0).getId()).isEqualTo("EUVD-2026-1");
        }
        assertThat(store.get("watermark").value()).isEqualTo("2026-03-05");
        verify(getRequestedFor(urlPathEqualTo("/api/search")).withQueryParam("fromUpdatedDate", equalTo("2026-03-04")));
    }

    @Test
    void shouldCommitOnlyAfterSuccessfulAcknowledgement(WireMockRuntimeInfo info) {
        pages();
        final var store = new MockKeyValueStore();
        store.put("watermark", "2026-03-05");
        try (final var source = source(info, store, "2026-03-06")) {
            final var bom = source.next();
            assertThat(source.hasNext()).isFalse();
            source.markProcessed(bom);
            assertThat(store.get("watermark").value()).isEqualTo("2026-03-06");
        }
        assertThat(store.get("watermark").value()).isEqualTo("2026-03-06");
    }

    @Test
    void shouldNotCommitOnPageFailureOrEarlyClose(WireMockRuntimeInfo info) {
        pages();
        final var store = new MockKeyValueStore();
        store.put("watermark", "2026-03-05");
        try (final var source = source(info, store, "2026-03-06")) {
            source.markProcessed(source.next());
        }
        assertThat(store.get("watermark").value()).isEqualTo("2026-03-05");
        stubFor(get(urlPathEqualTo("/api/search"))
                .withQueryParam("page", equalTo("1"))
                .willReturn(aResponse().withStatus(500)));
        try (final var source = source(info, store, "2026-03-06")) {
            source.markProcessed(source.next());
            assertThatThrownBy(source::hasNext).isInstanceOf(java.io.UncheckedIOException.class);
        }
        assertThat(store.get("watermark").value()).isEqualTo("2026-03-05");
    }

    @Test
    void shouldNotCommitAfterInterruption(WireMockRuntimeInfo info) {
        pages();
        final var store = new MockKeyValueStore();
        store.put("watermark", "2026-03-05");
        try (final var source = source(info, store, "2026-03-06")) {
            source.markProcessed(source.next());
            Thread.currentThread().interrupt();
            assertThat(source.hasNext()).isFalse();
            // Host close temporarily clears interruption; failed state must still prevent commit.
            assertThat(Thread.interrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
        assertThat(store.get("watermark").value()).isEqualTo("2026-03-05");
    }

    @Test
    void shouldKeepCompletedWindowWhenNextWindowFails(WireMockRuntimeInfo info) {
        stubFor(get(urlPathEqualTo("/api/search")).willReturn(aResponse().withStatus(500)));
        stubFor(get(urlPathEqualTo("/api/search"))
                .withQueryParam("toUpdatedDate", equalTo("1999-12-31"))
                .willReturn(okJson("{\"items\":[],\"total\":0}")));
        final var store = new MockKeyValueStore();
        try (final var source = source(info, store, "2000-01-31")) {
            assertThatThrownBy(source::hasNext).isInstanceOf(java.io.UncheckedIOException.class);
            assertThat(store.get("watermark").value()).isEqualTo("1999-12-31");
        }
        assertThat(store.get("watermark").value()).isEqualTo("1999-12-31");
    }

    @Test
    void shouldCommitWindowsInOrderAsTheyAreAcknowledged(WireMockRuntimeInfo info) {
        pages();
        final var store = new MockKeyValueStore();
        try (final var source = source(info, store, "2000-01-31")) {
            final var first = source.next();
            final var second = source.next();
            assertThat(store.get("watermark")).isNull();
            source.markProcessed(first);
            assertThat(store.get("watermark").value()).isEqualTo("1999-12-31");
            assertThat(source.hasNext()).isFalse();
            assertThat(store.get("watermark").value()).isEqualTo("1999-12-31");
            source.markProcessed(second);
            assertThat(store.get("watermark").value()).isEqualTo("2000-01-31");
        }
    }

    @Test
    void shouldNotCommitLaterWindowsBeforeEarlierAcknowledgements(WireMockRuntimeInfo info) {
        pages();
        final var store = new MockKeyValueStore();
        try (final var source = source(info, store, "2000-01-31")) {
            final var first = source.next();
            final var second = source.next();
            assertThat(source.hasNext()).isFalse();
            source.markProcessed(second);
            assertThat(store.get("watermark")).isNull();
            source.markProcessed(first);
            assertThat(store.get("watermark").value()).isEqualTo("2000-01-31");
        }
    }

    private void pages() {
        stubFor(get(urlPathEqualTo("/api/search"))
                .withQueryParam("page", equalTo("0"))
                .willReturn(okJson("{\"items\":[{\"id\":\"EUVD-2026-1\"}],\"total\":1}")));
        stubFor(get(urlPathEqualTo("/api/search"))
                .withQueryParam("page", equalTo("1"))
                .willReturn(okJson("{\"items\":[],\"total\":1}")));
    }
}
