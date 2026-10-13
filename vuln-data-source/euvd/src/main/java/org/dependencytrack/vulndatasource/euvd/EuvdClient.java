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
import org.dependencytrack.support.net.HttpRetry;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.dependencytrack.vulndatasource.euvd.model.EuvdVulnerabilitiesPage;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;

final class EuvdClient {
    static final String DEFAULT_API_BASE_URL = "https://euvdservices.enisa.europa.eu";
    private static final ObjectMapper JSON = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    private final HttpClient httpClient;
    private final String apiUrl;
    private final OutboundConnectionPolicy policy;

    EuvdClient(HttpClient httpClient, String apiUrl, OutboundConnectionPolicy policy) {
        this.httpClient = httpClient;
        this.apiUrl = apiUrl.replaceAll("/+$", "");
        this.policy = policy;
    }

    EuvdVulnerabilitiesPage search(@Nullable LocalDate from, LocalDate to, int page, int size)
            throws IOException, InterruptedException {
        if (page < 0 || size < 1 || size > 100 || (from != null && from.isAfter(to))) {
            throw new IllegalArgumentException("Invalid EUVD search parameters");
        }
        final URI uri = URI.create(apiUrl + "/api/search?"
                + (from == null ? "" : "fromUpdatedDate=" + from + "&")
                + "toUpdatedDate=" + to + "&page=" + page + "&size=" + size);
        policy.requireAllowed(uri.getHost());
        final HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json")
                .GET()
                .build();
        for (int attempt = 0; ; attempt++) {
            if (Thread.interrupted()) {
                throw new InterruptedException("EUVD search interrupted");
            }
            final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            final HttpRetry retry = HttpRetry.of(response);
            if ((retry.isRetryable() || response.statusCode() == 403) && attempt < 5) {
                final Duration retryAfter = retry.retryAfter();
                final Duration delay = retryAfter == null
                        ? Duration.ofSeconds(2L << attempt)
                        : retryAfter.compareTo(Duration.ofSeconds(60)) > 0 ? Duration.ofSeconds(60) : retryAfter;
                Thread.sleep(delay);
                continue;
            }
            if (response.statusCode() != 200) {
                throw new IOException("Unexpected EUVD response status: " + response.statusCode());
            }
            final var json = JSON.readTree(response.body());
            if (json == null
                    || !json.path("items").isArray()
                    || !json.path("total").canConvertToInt()
                    || !json.path("total").isIntegralNumber()
                    || json.path("total").intValue() < 0) {
                throw new IOException("Invalid EUVD search response");
            }
            if (json.path("items").size() > size) {
                throw new IOException("EUVD response exceeds requested page size");
            }
            for (final var item : json.path("items")) {
                if (!item.isObject()) {
                    throw new IOException("Invalid EUVD advisory");
                }
            }
            return JSON.treeToValue(json, EuvdVulnerabilitiesPage.class);
        }
    }
}
