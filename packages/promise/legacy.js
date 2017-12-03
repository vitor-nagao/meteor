// In legacy environments, load a polyfill if global.Promise was not
// defined in modern.js.
Promise = Promise || require("promise/lib/es6-extensions");
