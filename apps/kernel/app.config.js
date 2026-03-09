const projectId = process.env.EXPO_PUBLIC_EXPO_PROJECT_ID || process.env.EAS_PROJECT_ID || '00000000-0000-0000-0000-000000000000';
const androidPackage = process.env.ANDROID_APPLICATION_ID || 'com.opensentinel.kernel';
const iosBundleIdentifier = process.env.IOS_BUNDLE_IDENTIFIER || 'com.opensentinel.kernel';

module.exports = {
  expo: {
    name: 'OpenSentinel',
    slug: 'opensentinel',
    version: '1.0.0',
    orientation: 'portrait',
    icon: './assets/icon.png',
    userInterfaceStyle: 'light',
    scheme: 'opensentinel',
    splash: {
      image: './assets/splash-icon.png',
      resizeMode: 'contain',
      backgroundColor: '#ffffff',
    },
    ios: {
      supportsTablet: true,
      bundleIdentifier: iosBundleIdentifier,
    },
    android: {
      package: androidPackage,
      permissions: [
        'USE_BIOMETRIC',
        'USE_FINGERPRINT',
        'POST_NOTIFICATIONS',
        'RECEIVE_BOOT_COMPLETED',
        'VIBRATE',
      ],
      adaptiveIcon: {
        backgroundColor: '#E6F4FE',
        foregroundImage: './assets/android-icon-foreground.png',
        backgroundImage: './assets/android-icon-background.png',
        monochromeImage: './assets/android-icon-monochrome.png',
      },
    },
    plugins: [
      'expo-dev-client',
      'expo-secure-store',
      [
        'expo-notifications',
        {
          icon: './assets/icon.png',
          color: '#e83e5a',
          defaultChannel: 'approval-alerts',
        },
      ],
    ],
    extra: {
      eas: {
        projectId,
      },
    },
    web: {
      favicon: './assets/favicon.png',
    },
  },
};