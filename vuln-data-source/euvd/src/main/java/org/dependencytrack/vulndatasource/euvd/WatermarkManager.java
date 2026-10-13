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

import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jspecify.annotations.Nullable;

import java.time.LocalDate;

final class WatermarkManager {
    private final KeyValueStore store;
    private @Nullable LocalDate watermark;
    private @Nullable Long version;

    WatermarkManager(KeyValueStore store) {
        this.store = store;
        final var entry = store.get("watermark");
        watermark = entry == null ? null : LocalDate.parse(entry.value());
        version = entry == null ? null : entry.version();
    }

    @Nullable
    LocalDate getWatermark() {
        return watermark;
    }

    void commit(LocalDate date) {
        if (watermark != null && !date.isAfter(watermark)) {
            return;
        }
        final var result = store.compareAndPut("watermark", date.toString(), version);
        if (result instanceof CompareAndPutResult.Failure failure) {
            throw new IllegalStateException("Failed to commit EUVD watermark: " + failure.reason());
        }
        version = ((CompareAndPutResult.Success) result).newVersion();
        watermark = date;
    }
}
