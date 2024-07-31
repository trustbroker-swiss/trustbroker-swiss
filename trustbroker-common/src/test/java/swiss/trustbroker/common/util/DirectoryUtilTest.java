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

package swiss.trustbroker.common.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

@SpringBootTest
@ContextConfiguration(classes = { DirectoryUtil.class })
class DirectoryUtilTest {

	@Autowired
	DirectoryUtil directoryUtil;

	private static File tempDir;

	@BeforeAll
	static void setUp() throws IOException {
		tempDir = Files.createTempDirectory("DirectoryUtilTest").toFile();
	}

	@AfterAll
	static void tearDown() throws IOException {
		if (tempDir != null) {
			FileUtils.deleteDirectory(tempDir);
		}
	}

	@Test
	void backupDirectory() throws IOException  {
		var oldDir = existingDir(tempDir, "bak");
		var newDir = existingDir(tempDir, "new");
		var subdir = existingDir(newDir, "sub");
		directoryUtil.backupDirectory(newDir, oldDir);
		assertTrue(oldDir.exists());
		assertFalse(newDir.exists());
		assertTrue(new File(oldDir, "sub").exists());
	}

	@Test
	void restoreBackup() throws IOException  {
		var oldDir = existingDir(tempDir, "bak");
		var subdir = existingDir(oldDir, "sub"); // moved to new
		var newDir = missingDir(tempDir, "new");
		var subdirNew = missingDir(newDir, "sub");
		directoryUtil.restoreBackup(newDir, oldDir);
		assertFalse(oldDir.exists());
		assertTrue(newDir.exists());
		assertFalse(subdir.exists());
		assertTrue(subdirNew.exists());
	}

	@Test
	void restoreBackupDeleteCurrent() throws IOException  {
		var oldDir = existingDir(tempDir, "bak");
		var subdir = existingDir(oldDir, "sub"); // moved to new
		var newDir = existingDir(tempDir, "new");
		var subdirNew = missingDir(newDir, "sub");
		var subToClean = existingDir(newDir, "clean"); // deleted
		directoryUtil.restoreBackup(newDir, oldDir);
		assertFalse(oldDir.exists());
		assertFalse(subToClean.exists());
		assertFalse(subdir.exists());
		assertTrue(newDir.exists());
		assertTrue(subdirNew.exists());
	}


	@Test
	void restoreMissingBackup() throws IOException  {
		var oldDir = missingDir(tempDir, "bak");
		var newDir = existingDir(tempDir, "new");
		var subdir = existingDir(newDir, "sub"); // retained
		directoryUtil.restoreBackup(newDir, oldDir);
		assertFalse(oldDir.exists());
		assertTrue(newDir.exists());
		assertTrue(subdir.exists());
	}

	private File existingDir(File parent, String name) {
		var subdir = new File(parent, name);
		subdir.mkdirs();
		return subdir;
	}

	private File missingDir(File parent, String name) throws IOException {
		var subdir = new File(parent, name);
		FileUtils.deleteDirectory(subdir);
		return subdir;
	}
}
