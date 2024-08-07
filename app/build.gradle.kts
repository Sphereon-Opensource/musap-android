plugins {
    id("com.android.library")
    id("maven-publish")
}

android {
    namespace = "fi.methics.musapsdk"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {

    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.10.0")
    implementation("com.yubico.yubikit:piv:2.3.0")
    implementation("com.yubico.yubikit:android:2.3.0")
    implementation("com.google.code.gson:gson:2.8.8")
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.71")
    implementation("com.squareup.okhttp3:okhttp:4.10.0")
    implementation("androidx.navigation:navigation-fragment:2.7.5")
    implementation("androidx.navigation:navigation-ui:2.7.5")
    implementation("com.github.tony19:logback-android:3.0.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.9")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "fi.methics.musap"
                artifactId = "musap-android"
                version = "1.1.10"
            }
        }
        repositories {
            maven {
                val releasesRepoUrl = uri("https://nexus.sphereon.com/repository/sphereon-opensource-releases/")
                val snapshotsRepoUrl = uri("https://nexus.sphereon.com/repository/sphereon-opensource-snapshots/")
                url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl


                /**
                 * Make sure you have the below properties in the gradle.properties file in your local .gradle folder
                 */
                val mavenUser: String? by project
                val mavenPassword: String? by project


                credentials {
                    username = mavenUser
                    password = mavenPassword
                }
            }
        }
    }
}
