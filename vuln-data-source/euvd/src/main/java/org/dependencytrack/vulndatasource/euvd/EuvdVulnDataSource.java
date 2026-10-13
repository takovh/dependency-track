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

import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.euvd.model.EuvdVulnerability;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.LocalDate;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.NoSuchElementException;
import java.util.Set;

final class EuvdVulnDataSource implements VulnDataSource {
    private static final Logger LOGGER = LoggerFactory.getLogger(EuvdVulnDataSource.class);
    private final Set<String> windowIds = new HashSet<>();
    private int previousTotal = -1;
    private final EuvdClient client;
    private final WatermarkManager watermark;
    private final LocalDate end;
    private final Deque<EuvdVulnerability> buffer = new ArrayDeque<>();
    private final IdentityHashMap<Bom, LocalDate> unprocessed = new IdentityHashMap<>();
    private final Deque<LocalDate> completedWindows = new ArrayDeque<>();
    private @Nullable LocalDate from;
    private LocalDate windowEnd;
    private int page;
    private boolean windowDrained;
    private boolean exhausted;
    private boolean failed;
    private boolean closed;

    EuvdVulnDataSource(EuvdClient client, WatermarkManager watermark, LocalDate end) {
        this.client = client;
        this.watermark = watermark;
        this.end = end;
        final LocalDate committed = watermark.getWatermark();
        if (committed != null && committed.isAfter(end)) {
            throw new IllegalStateException("EUVD watermark is in the future");
        }
        from = committed == null ? null : committed.minusDays(1);
        if (from == null) {
            windowEnd = LocalDate.of(1999, 12, 31);
        } else {
            final LocalDate monthEnd = from.withDayOfMonth(from.lengthOfMonth());
            windowEnd = monthEnd.isAfter(end) ? end : monthEnd;
        }
    }

    @Override
    public boolean hasNext() {
        if (closed || failed) {
            throw new IllegalStateException("EUVD source is closed or failed");
        }
        try {
            while (buffer.isEmpty() && !exhausted) {
                if (Thread.currentThread().isInterrupted()) {
                    failed = true;
                    return false;
                }
                if (windowDrained) {
                    if (!windowEnd.isBefore(end)) {
                        exhausted = true;
                        break;
                    }
                    from = windowEnd.plusDays(1);
                    final LocalDate monthEnd = from.withDayOfMonth(from.lengthOfMonth());
                    windowEnd = monthEnd.isAfter(end) ? end : monthEnd;
                    page = 0;
                    previousTotal = -1;
                    windowIds.clear();
                    windowDrained = false;
                }
                final var result = client.search(from, windowEnd, page++, 100);
                if (previousTotal != -1 && previousTotal != result.total()) {
                    LOGGER.warn(
                            "EUVD result count changed in window {}..{}: {} -> {}",
                            from,
                            windowEnd,
                            previousTotal,
                            result.total());
                }
                previousTotal = result.total();
                for (final var advisory : result.items()) {
                    if (!windowIds.add(advisory.id())) {
                        LOGGER.debug("Duplicate EUVD ID {} in window {}..{}", advisory.id(), from, windowEnd);
                    }
                }
                buffer.addAll(result.items());
                // Only an empty page terminates a window: totals can change while paging.
                windowDrained = result.items().isEmpty();
                if (windowDrained) {
                    completedWindows.addLast(windowEnd);
                    commitCompletedWindows();
                }
            }
            return !buffer.isEmpty();
        } catch (InterruptedException e) {
            failed = true;
            Thread.currentThread().interrupt();
            return false;
        } catch (IOException e) {
            failed = true;
            throw new UncheckedIOException(e);
        } catch (RuntimeException e) {
            failed = true;
            throw e;
        }
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        try {
            final Bom bom = ModelConverter.convert(buffer.removeFirst());
            unprocessed.put(bom, windowEnd);
            return bom;
        } catch (RuntimeException e) {
            failed = true;
            throw e;
        }
    }

    @Override
    public void markProcessed(Bom bom) {
        if (unprocessed.remove(bom) == null) {
            failed = true;
            throw new IllegalArgumentException("BOV was not emitted or was already acknowledged");
        }
        try {
            commitCompletedWindows();
        } catch (RuntimeException e) {
            failed = true;
            throw e;
        }
    }

    private void commitCompletedWindows() {
        if (closed || failed || Thread.currentThread().isInterrupted()) {
            return;
        }
        while (!completedWindows.isEmpty()) {
            final LocalDate completedWindow = completedWindows.getFirst();
            if (unprocessed.values().stream().anyMatch(date -> !date.isAfter(completedWindow))) {
                return;
            }
            watermark.commit(completedWindow);
            completedWindows.removeFirst();
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        buffer.clear();
        unprocessed.clear();
        completedWindows.clear();
        windowIds.clear();
    }
}
