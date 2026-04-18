# ============================================================
# SentinelNode Elite — ProGuard / R8 rules
# ============================================================

# ---- Android system components (must not be renamed) -------
-keep class com.flow.validator.admin.AdminReceiver         { *; }
-keep class com.flow.validator.vpn.ValidatorVpnService     { *; }
-keep class com.flow.validator.service.MainService         { *; }
-keep class com.flow.validator.service.BootReceiver        { *; }
-keep class com.flow.validator.audit.LogAnalyzer           { *; }
-keep interface com.flow.validator.audit.LogAnalyzer$*     { *; }
-keep class com.flow.validator.ui.**                       { *; }

# ---- MITM / crypto layer -----------------------------------
# CertificateManager uses reflection internally (BC provider)
-keep class com.flow.validator.mitm.**                     { *; }
-keep class com.flow.validator.vpn.TunChannel              { *; }
-keep class com.flow.validator.vpn.PacketParser            { *; }
-keep class com.flow.validator.util.**                     { *; }

# ---- BouncyCastle ------------------------------------------
# BC uses provider registry + reflection; keep all public API
-keep class org.bouncycastle.**                            { *; }
-dontwarn org.bouncycastle.**
-keep class org.spongycastle.**                            { *; }
-dontwarn org.spongycastle.**

# BC PKIX certificate builder / converter
-keep class org.bouncycastle.cert.**                       { *; }
-keep class org.bouncycastle.operator.**                   { *; }
-keep class org.bouncycastle.asn1.**                       { *; }
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }

# ---- JDK SSL / TLS -----------------------------------------
-keep class javax.net.ssl.**                               { *; }
-dontwarn javax.net.ssl.**
-keep class java.security.**                               { *; }

# ---- NIO channels (TunChannel / FileChannel) ---------------
-keep class java.nio.channels.**                           { *; }
-keep class java.nio.ByteBuffer                            { *; }

# ---- ForkJoinPool ------------------------------------------
-keep class java.util.concurrent.ForkJoinPool             { *; }
-keep class java.util.concurrent.ForkJoinTask             { *; }
-dontwarn java.util.concurrent.ForkJoinPool

# ---- AndroidX / AppCompat ----------------------------------
-keep class androidx.**                                    { *; }
-dontwarn androidx.**

# ---- General ------------------------------------------------
-dontwarn android.app.admin.**
-dontwarn android.net.VpnService.**
-keepattributes Signature, InnerClasses, EnclosingMethod
-keepattributes *Annotation*
