unit module MyCrypto::BlackBox;

use MyCrypto::Ciphers;

class BlackBox is export {
    has Blob $!iv;
    has Blob $!key;

    has Str $!mode;
    has Str @!modes;

    multi method init() {
        @!modes = 'ecb', 'cbc';
    }

    multi method init(:$ecb! where .so) {
        @!modes = 'ecb';
    }

    method reset() {
        $!mode = @!modes.pick;

        $!iv = '/dev/urandom'.IO.open(:bin, :ro).read(16);
        $!key = '/dev/urandom'.IO.open(:bin, :ro).read(16);
    }

    method encrypt(Blob $input) {
        return encrypt-aes($input, :$!key) if $!mode eq 'ecb';
        return encrypt-aes-cbc($input, :$!iv, :$!key) if $!mode eq 'cbc';
    }

    method decrypt(Blob $input) {
        return decrypt-aes($input, :$!key) if $!mode eq 'ecb';
        return decrypt-aes-cbc($input, :$!iv, :$!key) if $!mode eq 'cbc';
    }

    method check(:$mode) {
        return False if (defined $mode) && ($mode ne $!mode);

        return True;
    }
}
