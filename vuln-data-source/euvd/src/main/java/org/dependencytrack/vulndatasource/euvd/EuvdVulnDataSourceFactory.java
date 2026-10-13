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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.dependencytrack.vulndatasource.euvd.model.EuvdVulnerabilitiesPage;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDate;
import java.time.ZoneOffset;

import static java.util.Objects.requireNonNull;

final class EuvdVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable, Testable {
    private @Nullable ExtensionContext context;

    @Override
    public String extensionName() {
        return "euvd";
    }

    @Override
    public String displayName() {
        return "EUVD";
    }

    @Override
    public Class<? extends VulnDataSource> extensionClass() {
        return EuvdVulnDataSource.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST + 100;
    }

    @Override
    public void init(ExtensionContext context) {
        this.context = context;
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new EuvdVulnDataSourceConfigV1()
                        .withEnabled(true)
                        .withApiUrl(URI.create(EuvdClient.DEFAULT_API_BASE_URL)),
                config -> {
                    if (config.isEnabled() && config.getApiUrl() != null) {
                        validateUrl(config.getApiUrl());
                    }
                });
    }

    private static void validateUrl(@Nullable URI uri) {
        if (uri == null
                || uri.getHost() == null
                || !("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null
                || uri.getRawUserInfo() != null) {
            throw new InvalidRuntimeConfigException(
                    "EUVD apiUrl must be an HTTP(S) URL without credentials, query or fragment");
        }
    }

    @Override
    public boolean isDataSourceEnabled() {
        return requireNonNull(context)
                .configRegistry()
                .getRuntimeConfig(EuvdVulnDataSourceConfigV1.class)
                .isEnabled();
    }

    private EuvdClient client(EuvdVulnDataSourceConfigV1 config) {
        final var ctx = requireNonNull(context);
        final URI uri = config.getApiUrl() == null ? URI.create(EuvdClient.DEFAULT_API_BASE_URL) : config.getApiUrl();
        validateUrl(uri);
        return new EuvdClient(ctx.httpClient(), uri.toString(), ctx.outboundConnectionPolicy());
    }

    @Override
    public VulnDataSource create() {
        final var ctx = requireNonNull(context);
        final var config = ctx.configRegistry().getRuntimeConfig(EuvdVulnDataSourceConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("EUVD data source is disabled");
        }
        return new EuvdVulnDataSource(
                client(config), new WatermarkManager(ctx.keyValueStore()), LocalDate.now(ZoneOffset.UTC));
    }

    @Override
    public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
        final var config = (EuvdVulnDataSourceConfigV1) requireNonNull(runtimeConfig);
        final var result = ExtensionTestResult.ofChecks("connection", "feed_format");
        if (!config.isEnabled()) {
            return result;
        }
        final EuvdVulnerabilitiesPage response;
        try {
            response = client(config).search(null, LocalDate.now(ZoneOffset.UTC), 0, 1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return result.fail("connection", "EUVD probe interrupted");
        } catch (IOException | RuntimeException e) {
            return result.fail("connection", "EUVD connection or response validation failed");
        }
        result.pass("connection");
        try {
            for (final var advisory : response.items()) {
                ModelConverter.convert(advisory);
            }
            return result.pass("feed_format");
        } catch (RuntimeException e) {
            return result.fail("feed_format", "EUVD advisory format validation failed");
        }
    }
}
