window.onloadTurnstileCallback = function () {
  turnstile.render("#pf-turnstyle", {
    sitekey: "0x4AAAAAABmEkyfvX0lChkqk",
    callback: function (token) {
      console.log(`Challenge Success ${token}`);
    },
    appearance: "interaction-only",
    language: "auto",
  });
};