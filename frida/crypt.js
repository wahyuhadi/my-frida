console.log("Script loaded successfully");


Java.perform(function x() {
    var secret_key_spec = Java.use("javax.crypto.spec.SecretKeySpec");
    
    
    secret_key_spec.$init.overload("[B", "java.lang.String").implementation = function (x, y) {
        send('{"my_type" : "KEY"}', new Uint8Array(x));
        return this.$init(x, y);
    }

    //hooking IvParameterSpec's constructor to get the IV as we got the key above.
    var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
    iv_parameter_spec.$init.overload("[B").implementation = function (x) {
        send('{"my_type" : "IV"}', new Uint8Array(x));
        return this.$init(x);
    }

    var cipher = Java.use("javax.crypto.Cipher");
    cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (x, y, z) {
        if (x == 1) 
            send('{"my_type" : "hashcode_enc", "hashcode" :"' + this.hashCode().toString() + '" }');
        else // In this android app it is either 1 (Cipher.MODE_ENCRYPT) or 2 (Cipher.MODE_DECRYPT)
            send('{"my_type" : "hashcode_dec", "hashcode" :"' + this.hashCode().toString() + '" }');

        //Also we can obtain the key,iv from the args passed to init call
        send('{"my_type" : "Key from call to cipher init"}', new Uint8Array(y.getEncoded()));
        //arg z is of type AlgorithmParameterSpec, we need to cast it to IvParameterSpec first to be able to call getIV function
        send('{"my_type" : "IV from call to cipher init"}', new Uint8Array(Java.cast(z, iv_parameter_spec).getIV()));
        //init must be called this way to work properly
        return cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").call(this, x, y, z);

    }

    cipher.doFinal.overload("[B").implementation = function (x) {
        send('{"my_type" : "before_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(x));
        var ret = cipher.doFinal.overload("[B").call(this, x);
        send('{"my_type" : "after_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(ret));

        return ret;
    }
});