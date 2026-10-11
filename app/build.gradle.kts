plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val signingEnvironment = listOf(
    System.getenv("GSM2SIP_SIGNING_KEYSTORE"),
    System.getenv("GSM2SIP_SIGNING_STORE_PASSWORD"),
    System.getenv("GSM2SIP_SIGNING_KEY_ALIAS"),
    System.getenv("GSM2SIP_SIGNING_KEY_PASSWORD")
)
require(signingEnvironment.all { it.isNullOrBlank() } || signingEnvironment.all { !it.isNullOrBlank() }) {
    "Set all four GSM2SIP_SIGNING_* environment variables to use a fixed signing key"
}
val fixedSigningEnabled = signingEnvironment.all { !it.isNullOrBlank() }

android {
    namespace = "com.callagent.gateway"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.callagent.gateway"
        minSdk = 26
        targetSdk = 34
        versionCode = 425
        versionName = "1.2.0"
    }

    // A fixed keystore can be provided for repeatable fork builds. If absent,
    // preserve the project's existing shared debug-key behavior for local builds.
    signingConfigs {
        create("shared") {
            if (fixedSigningEnabled) {
                storeFile = file(requireNotNull(System.getenv("GSM2SIP_SIGNING_KEYSTORE")))
                storePassword = requireNotNull(System.getenv("GSM2SIP_SIGNING_STORE_PASSWORD"))
                keyAlias = requireNotNull(System.getenv("GSM2SIP_SIGNING_KEY_ALIAS"))
                keyPassword = requireNotNull(System.getenv("GSM2SIP_SIGNING_KEY_PASSWORD"))
            } else {
                storeFile = file(System.getProperty("user.home") + "/.android/debug.keystore")
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("shared")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    testImplementation("junit:junit:4.13.2")
}
