#!/usr/bin/bash
set -e
set -x
# You need to fix the suffix: 7O3ynhSmMsg2_E5_uqbQxQ==
adb push ./libnative-lib-patched.so /data/local/tmp/libnative-lib-patched.so
adb shell su -c cp \
  /data/local/tmp/libnative-lib-patched.so \
  /data/app/re.pwnme-7O3ynhSmMsg2_E5_uqbQxQ==/lib/arm64/libnative-lib.so

adb shell su -c chown system:system /data/app/re.pwnme-7O3ynhSmMsg2_E5_uqbQxQ==/lib/arm64/libnative-lib.so
adb shell su -c chmod 777 /data/app/re.pwnme-7O3ynhSmMsg2_E5_uqbQxQ==/lib/arm64/libnative-lib.so
adb shell su -c chcon "u:object_r:apk_data_file:s0" /data/app/re.pwnme-7O3ynhSmMsg2_E5_uqbQxQ==/lib/arm64/libnative-lib.so

