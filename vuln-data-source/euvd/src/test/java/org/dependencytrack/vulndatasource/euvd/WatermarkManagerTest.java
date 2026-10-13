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

import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WatermarkManagerTest {
    @Test
    void shouldDetectConcurrentWatermarkChanges() {
        final var store = new MockKeyValueStore();
        final var manager = new WatermarkManager(store);
        store.put("watermark", "2026-03-05");
        assertThatThrownBy(() -> manager.commit(LocalDate.parse("2026-03-06")))
                .isInstanceOf(IllegalStateException.class);
        assertThat(store.get("watermark").value()).isEqualTo("2026-03-05");
    }

    @Test
    void shouldRejectInvalidStoredDate() {
        final var store = new MockKeyValueStore();
        store.put("watermark", "invalid");
        assertThatThrownBy(() -> new WatermarkManager(store))
                .isInstanceOf(java.time.format.DateTimeParseException.class);
    }
}
