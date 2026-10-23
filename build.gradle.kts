// The plugins' classpath: raise jars AGP 9.4.1 pulls in that trivy flags to
// their fixed releases. A constraint only lifts a module already in the graph.
buildscript {
    dependencies {
        constraints {
            // bcprov-jdk18on 1.80.2 (CVE-2026-8763, CVE-2026-13506), from AGP's
            // builder and sdk-common; bcpkix and bcutil 1.80.2 come with it, and
            // Bouncy Castle releases the three as one set.
            classpath(libs.bouncycastle.bcprov)
            classpath(libs.bouncycastle.bcpkix)
            classpath(libs.bouncycastle.bcutil)
            // jose4j 0.9.5 (CVE-2024-29371), from bundletool 1.18.3
            classpath(libs.jose4j)
            // jdom2 2.0.6 (CVE-2021-33813), from jetifier-processor 1.0.0-beta10
            classpath(libs.jdom2)
        }
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
