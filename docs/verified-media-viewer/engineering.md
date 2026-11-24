# Verified media viewer

> **Status: REFERENCE** · Last verified: 2026-11-23
> Engineering reference for `VerifiedMediaViewerActivity`: intents, rendering, the overlay rows, and the audit entry.

How the viewer finds signatures and decides each signer is in
[architecture.md](architecture.md).

## Intents

```xml
<activity
    android:name=".ui.VerifiedMediaViewerActivity"
    android:exported="true"
    android:label="@string/verified_viewer_title">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="image/*" />
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="video/*" />
    </intent-filter>
</activity>
```

`resolveMediaUri` takes `intent.data`, or `EXTRA_STREAM` when there is no
data. The manifest has no `SEND` filter, so `EXTRA_STREAM` is used only by an
explicit intent. With neither, the activity finishes at once.

The MIME type is `ContentResolver.getType(uri)`, falling back to
`intent.type`. A type starting with `video/` plays as video; anything else is
shown as an image.

## Image rendering

`showImage` decodes on `Dispatchers.IO` in two passes. The first reads only
the bounds. `calculateInSampleSize` then picks the largest power of two that
keeps both halved dimensions at or above 2048 px (`MAX_BITMAP_DIMENSION`), and
the second pass decodes at that sample size. A 4000x3000 photo decodes at full
size; an 8000x6000 photo decodes at 4000x3000. A decode failure is logged and
the image area stays empty.

## Video rendering

`showVideo` builds a Media3 `ExoPlayer`, attaches it to the layout's
`PlayerView`, sets `MediaItem.fromUri(uri)`, and starts playback at once
(`playWhenReady = true`). The player is released in `onDestroy`.

## Layout

`res/layout/activity_verified_viewer.xml` is a `FrameLayout` with:

| View ID | Use |
|---------|-----|
| `imageView` | The image |
| `playerView` | The video player |
| `verificationOverlay` | Panel at the bottom, background `primary` at 80% alpha, set in code |
| `textVerificationTitle` | "Signers (N)" once signatures are found |
| `signerListContainer` | One row per signer, built in code |
| `textNoSignatures` | "No signatures found in this file" |

## Signer rows

Each row in `signerListContainer` has, left to right:

| Part | Content |
|------|---------|
| Dot | 12 dp circle: `security_verified` for verified, `security_warning` for unknown, `security_danger` for failed |
| Mark | ✓, ? or ✗ in the same colour |
| Name | `Result.displayName`, bold |
| Role | `CREATOR`, `WITNESS` or `ATTESTOR`, the enum name as stored |
| Time | The entry's timestamp as `yyyy-MM-dd HH:mm` in the local zone. An ISO 8601 instant or epoch milliseconds is parsed; anything else is shown as it is |

When `Result.claimedName` is set, an italic "Claims: <name>" line follows the
row. The row does not show the signature algorithm.

## Audit entry

After the rows are shown, the viewer calls
`AuditLogger.logFileVerified(fileName, signerCount, verified)`. `fileName` is
the URI's last path segment, and `verified` is true only when every signer
verified. Nothing is logged when no signatures were found or the check threw.

## Dependencies

| Library | Use |
|---------|-----|
| `androidx.media3:media3-exoplayer` | Video playback |
| `androidx.media3:media3-ui` | `PlayerView` |
| `androidx.exifinterface` | Reading the EXIF `UserComment` block |
