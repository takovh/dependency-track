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
import org.dependencytrack.plugin.api.ExtensionTestCheck;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.ExtensionContextBuilder;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

@WireMockTest
class EuvdVulnDataSourceFactoryTest extends AbstractExtensionFactoryTest<VulnDataSource, EuvdVulnDataSourceFactory> {
    EuvdVulnDataSourceFactoryTest() {
        super(EuvdVulnDataSourceFactory.class);
    }

    @Test
    void shouldProbeSearchWithTrailingSlash(WireMockRuntimeInfo info) {
        stubFor(get(urlPathEqualTo("/api/search")).willReturn(okJson("{\"items\":[],\"total\":0}")));
        factory.init(new ExtensionContextBuilder().build());
        final var config =
                new EuvdVulnDataSourceConfigV1().withEnabled(true).withApiUrl(URI.create(info.getHttpBaseUrl() + "/"));
        assertThat(factory.test(config).checks())
                .allSatisfy(check -> assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED));
    }
}
