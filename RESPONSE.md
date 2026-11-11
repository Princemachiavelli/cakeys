> One hash, not two: if the FOD output is the public key's DER encoding (or the certificate, or the 32-byte HMAC value for a secret key), the FOD hash is the key's identity digest. One hash in the lock.
Ideally yes but we need to allow multiple for variation between HSM. So myobject.fod.myhsm-named-bob gives the hsm specific digest.
In 99% of cases we should use myobject.fod.pubkeyhash or similar always-true value. Actually HSM specific CA identifier should emit warning/error because we can no longer garentee identity between TOKENS/HSMs.

> Caveat: once a FOD output is in the store or a binary cache, Nix never contacts the HSM again. A successful build proves the key existed once, not that it still does. Checking that it's still present needs a separate step, for example a check at NixOS activation.
Is there a way to prevent a Nix derivation from being cached at all?
Otherwise, instead of being a "true fod", just manually do a similar but not NIX check in the derivation that uses the key. So instead of getting the PKCS11 URI
or TPM2 ID directly, the derivation will call this tool like:
"URI=$(./key-mgmnt ${configFile} myobject.fod.pubkeyhash)"

The key-mgmnt will run the necessary pKCS11 operations to check that the key exists and get the hash and compare it against the values in configFile.
If this is first-use, the key will be created (i.e autoCreate=true is set in config for this template), then it gets FOD but forces build to fail i.e just like how
Nix FODs work but not "actually" a Nix FOD.

The real deraviton arround this gets requiredSystemFeatures like myObject.rsf.hsm-named-bob.

If Nix can do the above in a isolated derivation that's never cached, that's better but otherwise do this "pseudo-FOD" pre-use method.

> Parsec
Just use useful shared Rust crates and terms. Don't force over-use of it.

> 1. Slot attribute
Not quite sure what you mean. I think we must CKA_LABEL/CKA_ID to be arbitrary values. To the above "pseudo-FOD" pre-use check, we make throw failure if HSM contains
non-unique URIs. (The HAL layer should build in PKCS11 provider specific checks like this).

> 2. For now: Softhsm as referenc and starting point. Then Yubikey, Nitrokey, and HSM. Yubikey and HSM are present on system now. We will add CloudHSM and other HSM provides later.
Wide HSM support is an important feature.

> 3. Both.

> 4. I think both. Unless tpm2-pkcs11 can handle TPM specific things like PCR bindings.

> 5. One writter is fine.

> 6. Deleting the last copy? How would our tool know what's the last copy?

> 7. Sure SRI-256 is fine but don't stake the design on it. It sound like (due to issue with FOD) that we may not want to use true Nix FODS anyway.
