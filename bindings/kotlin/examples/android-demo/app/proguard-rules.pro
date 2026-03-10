# JNA keep rules
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn com.sun.jna.**

# IOTA SDK keep rules
-keep class iota_sdk.** { *; }
-dontwarn iota_sdk.**
