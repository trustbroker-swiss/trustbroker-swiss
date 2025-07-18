/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.federation.xmlconfig;

/**
 * Configuration for encryption key placement.
 *
 * @since 1.10.0
 */
public enum EncryptionKeyPlacement {
	/**
	 * <code>EncryptedKey</code> is placed as peer of code>KeyInfo</code>.
	 */
	PEER,
	/**
	 * <code>EncryptedKey</code> is within <code>KeyInfo</code>.
	 */
	INLINE
}
