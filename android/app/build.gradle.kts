plugins {
    id("com.android.application")
}

android {
    namespace = "com.jicloud.aiantiva"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.jicloud.aiantiva"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
