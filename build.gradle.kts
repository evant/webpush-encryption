plugins {
    id("java-library")
    id("org.jetbrains.kotlin.jvm") version "1.8.0"
    `maven-publish`
    signing
}

kotlin {
    jvmToolchain(11)
}

dependencies {
    api("com.squareup.okio:okio:3.3.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.willowtreeapps.assertk:assertk:0.25")
}

version = "0.1"

publishing {
    publications {
        create<MavenPublication>("release") {
            groupId = "me.tatarka.webpush"
            artifactId = "webpush-encryption"

            afterEvaluate {
                from(components["java"])
            }

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