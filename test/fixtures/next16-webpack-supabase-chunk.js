// Reconstruída a partir do formato real do Next 16.4.5 (validado em projeto real); não é captura bruta.
(self["webpackChunk_N_E"] = self["webpackChunk_N_E"] || []).push([["app/page"],{

/***/ "(app-pages-browser)/./src/app/components/Checkout.tsx":
/*!*************************************************************!*\
  !*** ./src/app/components/Checkout.tsx ***!
  \*************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _supabase_supabase_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @supabase/supabase-js */ "(app-pages-browser)/./node_modules/@supabase/supabase-js/dist/index.mjs");

function Checkout() {
  const credentials = { password: "MinhaSenhaReal123" };
  const client = (0,_supabase_supabase_js__WEBPACK_IMPORTED_MODULE_0__.createClient)("https://xyz.supabase.co", "anon-key");
  return { credentials, client };
}

/***/ }),

/***/ "(app-pages-browser)/./node_modules/@supabase/auth-js/dist/module/GoTrueClient.js":
/*!****************************************************************************************!*\
  !*** ./node_modules/@supabase/auth-js/dist/module/GoTrueClient.js ***!
  \****************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/**
 * @example
 * const { data, error } = await supabase.auth.signUp({
 *   email: 'example@email.com',
 *   password: 'some-password',
 * })
 * @example
 * const { data, error } = await supabase.auth.updateUser({
 *   password: 'new-password',
 * })
 * @example
 * const { data, error } = await supabase.auth.resetPasswordForEmail('user@email.com', {
 *   password: 'example-password',
 * })
 */
class GoTrueClient {
  async signUp(credentials) {
    return credentials;
  }
}

/***/ })

}]);
