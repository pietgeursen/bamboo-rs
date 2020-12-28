(function() {var implementors = {};
implementors["curve25519_dalek"] = [{"text":"impl Zeroize for Scalar","synthetic":false,"types":[]},{"text":"impl Zeroize for MontgomeryPoint","synthetic":false,"types":[]}];
implementors["ed25519_dalek"] = [{"text":"impl Zeroize for SecretKey","synthetic":false,"types":[]},{"text":"impl Zeroize for ExpandedSecretKey","synthetic":false,"types":[]}];
implementors["merlin"] = [{"text":"impl Zeroize for Transcript","synthetic":false,"types":[]}];
implementors["zeroize"] = [];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()