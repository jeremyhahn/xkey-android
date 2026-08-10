# ProGuard rules for xKey
# https://developer.android.com/build/shrink-code

# Keep FIDO2/CTAP2 data classes for CBOR serialization
-keep class com.automatethethings.xkey.ctap.** { *; }

# Keep crypto classes
-keep class com.automatethethings.xkey.crypto.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Kotlin serialization (if used in future)
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# AndroidX
-keep class androidx.** { *; }
-keep interface androidx.** { *; }

# Material Components
-keep class com.google.android.material.** { *; }

# Keep generic signature for type safety
-keepattributes Signature

# Keep source file names and line numbers for crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
