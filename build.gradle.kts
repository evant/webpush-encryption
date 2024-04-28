plugins {
    id("java-library")
    id("org.jetbrains.kotlin.jvm") version "1.8.0"
    id("org.jetbrains.dokka") version "1.8.10"
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
    `maven-publish`
    signing
}

kotlin {
    jvmToolchain(11)
}

dependencies {
    api("com.squareup.okio:okio:3.9.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.willowtreeapps.assertk:assertk:0.25")
}

group = "me.tatarka.webpush"
version = "0.2.1-SNAPSHOT"

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(kotlin.sourceSets["main"].kotlin.srcDirs)
}

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(tasks.dokkaJavadoc.flatMap { it.outputDirectory })
}

nexusPublishing {
    repositories {
        sonatype()
    }
}

publishing {
    publications {
        create<MavenPublication>("release") {
            artifactId = "webpush-encryption"

            from(components["kotlin"])
            artifact(sourcesJar)
            artifact(javadocJar)

            pom {
                name.set("webpush-encryption")
                description.set("A lightweight webpush encryption/decryption library")
                url.set("https://github.com/evant/webpush-encryption")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("evant")
                        name.set("Eva Tatarka")
                    }
                }
                scm {
                    connection.set("https://github.com/evant/webpush-encryption.git")
                    developerConnection.set("https://github.com/evant/webpush-encryption.git")
                    url.set("https://github.com/evant/webpush-encryption")
                }
            }
        }
    }
}

signing {
    setRequired {
        findProperty("signing.keyId") != null
    }

    publishing.publications.all {
        sign(this)
    }
}