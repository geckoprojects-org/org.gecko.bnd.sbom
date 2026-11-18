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
package org.gecko.bnd.sbom;

import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.gecko.bnd.sbom.model.SbomCreator;

import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Processor;

/**
 * The creator of a component or of the SBOM as BSI TR-03183-2 §5.2.1/§5.2.2 asks for it: an
 * email address, or else a URL (the creator's home page or the project's web page).
 * <p>
 * Both come from the OSGi headers — of a bundle's manifest, or of the bnd project the
 * {@code .bndrun} lives in: an email address in {@code Bundle-ContactAddress}, otherwise a URL
 * from there or from {@code Bundle-DocURL}. {@code Bundle-Vendor} is the creator's name; the TR
 * does not accept a name on its own, so it is written alongside.
 */
public final class Creators {

	/** deliberately simple: one address, no display name, no comments */
	private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

	private Creators() {}

	/** {@code true} for a single email address. */
	public static boolean isEmail(String value) {
		return value != null && EMAIL.matcher(value.trim())
			.matches();
	}

	/** {@code true} for an absolute http(s) URL. */
	public static boolean isUrl(String value) {
		return Limits.publishableUrl(value) != null;
	}

	/** The creator a bundle's manifest names, or {@code null}. */
	public static SbomCreator fromManifest(Manifest manifest) {
		if (manifest == null) {
			return null;
		}
		Attributes main = manifest.getMainAttributes();
		return of(main.getValue(Constants.BUNDLE_VENDOR), main.getValue(Constants.BUNDLE_CONTACTADDRESS),
			main.getValue(Constants.BUNDLE_DOCURL));
	}

	/** The creator a bnd project names in its properties, or {@code null}. */
	public static SbomCreator fromProperties(Processor properties) {
		if (properties == null) {
			return null;
		}
		return of(properties.getProperty(Constants.BUNDLE_VENDOR),
			properties.getProperty(Constants.BUNDLE_CONTACTADDRESS), properties.getProperty(Constants.BUNDLE_DOCURL));
	}

	/**
	 * The {@code creator} option: an email address or a URL, with the name of the vendor, if
	 * known, alongside.
	 */
	public static SbomCreator fromOption(String option, String vendor) {
		if (option == null) {
			return null;
		}
		return isEmail(option) ? SbomCreator.of(vendor, option.trim(), null)
			: SbomCreator.of(vendor, null, Limits.publishableUrl(option));
	}

	/** From the values of {@code Bundle-Vendor}, {@code Bundle-ContactAddress} and {@code Bundle-DocURL}. */
	static SbomCreator of(String vendor, String contact, String docUrl) {
		String email = findEmail(contact);
		String url = null;
		if (email == null) {
			url = Limits.publishableUrl(contact);
			if (url == null) {
				url = Limits.publishableUrl(docUrl);
			}
		}
		return SbomCreator.of(vendor, email, url);
	}

	/** The first email address in a free-text header such as {@code Bundle-ContactAddress}. */
	static String findEmail(String text) {
		if (text == null) {
			return null;
		}
		// a mailto: URL is an email address, too
		Matcher matcher = EMAIL.matcher(text);
		return matcher.find() ? matcher.group() : null;
	}
}
