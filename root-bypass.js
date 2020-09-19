// frida -U -l ./root-bypass.js --no-pause -f re.pwnme
Java.perform(function () {
  var RootCheck = Java.use('\u266b.\u1d64');

  RootCheck['₤'].implementation = function () {
    console.log("Skip root");
    return false;
  }

  RootCheck['θ'].overload().implementation = function () {
    console.log("Skip root");
    return false;
  }
})
