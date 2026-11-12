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
package org.gecko.bnd.sbom.serializer;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomRefs;

/**
 * The identity of one SBOM (#12): CycloneDX {@code serialNumber}, SPDX
 * {@code documentNamespace}.
 * <p>
 * By default a name-based UUID (version 5, SHA-1) over what makes two BOMs "the same": the
 * format, the level, the application and, in model order, every component's reference and
 * SHA-512. The creation time is deliberately not part of it — exporting an unchanged
 * application twice yields the same serial number (reproducible builds); any change to the
 * resolved set, a version or a file yields a new one. With {@code serialNumber=random} every
 * export gets a random UUID instead.
 */
public final class SerialNumbers {

	/** Namespace of the name-based UUIDs of this exporter (itself a random UUID, fixed). */
	static final UUID NAMESPACE = UUID.fromString("5f0a6e1c-8b0d-4e86-9c43-2a7d1e9b6f51");

	private SerialNumbers() {}

	public static UUID of(SbomModel model, SbomRefs refs, SbomConfig config) {
		if (config.randomSerialNumber()) {
			return UUID.randomUUID();
		}
		StringBuilder name = new StringBuilder();
		name.append(config.format()
			.id())
			.append('\n')
			.append(config.level()
				.id())
			.append('\n')
			.append(refs.application())
			.append('\n');
		for (SbomComponent component : model.getAllComponents()) {
			name.append(refs.of(component))
				.append(' ')
				.append(component.getSha512() != null ? component.getSha512() : "-")
				.append('\n');
		}
		return nameBased(NAMESPACE, name.toString());
	}

	/** {@code urn:uuid:} form, as CycloneDX requires for {@code serialNumber}. */
	public static String urn(UUID uuid) {
		return "urn:uuid:" + uuid;
	}

	/** RFC 9562 version 5 UUID. */
	static UUID nameBased(UUID namespace, String name) {
		MessageDigest sha1;
		try {
			sha1 = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-1 is required by every Java platform", e);
		}
		sha1.update(ByteBuffer.allocate(16)
			.putLong(namespace.getMostSignificantBits())
			.putLong(namespace.getLeastSignificantBits())
			.array());
		byte[] hash = sha1.digest(name.getBytes(StandardCharsets.UTF_8));
		hash[6] = (byte) ((hash[6] & 0x0f) | 0x50); // version 5
		hash[8] = (byte) ((hash[8] & 0x3f) | 0x80); // IETF variant
		ByteBuffer buffer = ByteBuffer.wrap(hash, 0, 16);
		return new UUID(buffer.getLong(), buffer.getLong());
	}
}
