/**
 * Copyright (c) 2012 - 2026 Data In Motion and others.
 * All rights reserved.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     Data In Motion - initial API and implementation
 */
package org.gecko.bnd.sbom.model;

/**
 * A tool that produced the SBOM (CycloneDX {@code metadata.tools}, SPDX {@code creators}).
 *
 * @param group may be {@code null}
 * @param version may be {@code null} when it cannot be determined
 * @param manufacturer may be {@code null}
 * @param purl may be {@code null}
 */
public record SbomTool(String group, String name, String version, String manufacturer, String purl) {}
