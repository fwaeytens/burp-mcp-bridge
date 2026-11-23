package com.example.burpmcp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class VersionTest {

    @Test
    public void versionComesFromThePomViaResourceFiltering() {
        // Under Maven, version.properties is filtered, so the dev placeholder
        // means the filtering (or the resource) is missing.
        assertNotEquals("0.0.0-dev", Version.VERSION);
        assertTrue("not a version: " + Version.VERSION,
                Version.VERSION.matches("\\d+\\.\\d+\\.\\d+([-.+][0-9A-Za-z.-]+)?"));
    }

    @Test
    public void shortVersionIsPrefixed() {
        assertEquals("v" + Version.VERSION, Version.getShortVersion());
    }
}
