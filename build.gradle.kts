// The plugins' classpath: raise jars AGP 9.0.0 pulls in that trivy flags to
// their fixed releases. A constraint only lifts a module already in the graph.
buildscript {
    dependencies {
        constraints {
            // bcprov-jdk18on 1.79, from AGP's builder 9.0.0 and sdk-common 32.0.0;
            // bcpkix 1.79 comes with it and bcutil 1.79 through bcpkix, and
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
