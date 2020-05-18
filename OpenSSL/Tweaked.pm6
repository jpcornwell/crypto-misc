unit module OpenSSL::Tweaked;

# This is just a copy of OpenSSL::CryptTools simplified and tweaked to include
# AES-128-ECB.

sub gen-lib { $*VM.platform-library-name('ssl'.IO).Str; }

use NativeCall;

my sub EVP_CIPHER_CTX_new(--> OpaquePointer) is native(&gen-lib) { ... }
my sub EVP_CIPHER_CTX_free(OpaquePointer) is native(&gen-lib) { ... }

my sub EVP_EncryptInit(OpaquePointer, OpaquePointer, Blob, Blob --> int32) is native(&gen-lib) { ... }
my sub EVP_EncryptUpdate(OpaquePointer, Blob, CArray[int32], Blob, int32 --> int32) is native(&gen-lib) { ... }
my sub EVP_EncryptFinal(OpaquePointer, Blob, CArray[int32] --> int32) is native(&gen-lib) { ... }

my sub EVP_DecryptInit(OpaquePointer, OpaquePointer, Blob, Blob --> int32) is native(&gen-lib) { ... }
my sub EVP_DecryptUpdate(OpaquePointer, Blob, CArray[int32], Blob, int32 --> int32) is native(&gen-lib) { ... }
my sub EVP_DecryptFinal(OpaquePointer, Blob, CArray[int32] --> int32) is native(&gen-lib) { ... }

my sub EVP_aes_128_ecb( --> OpaquePointer) is native(&gen-lib) { ... }

# Encrypts plaintext using aes-128-ecb
# Example: encrypt-aes("asdf".encode, :key(('x' x 32).encode));
sub encrypt-aes(Blob $plaintext, :$key) is export {
    my $cipher = EVP_aes_128_ecb();
    my $ctx = EVP_CIPHER_CTX_new();

    if $key.bytes != 16 {
        die "Key is not 128 bits";
    }

    # way bigger than needed
    my $bufsize = $plaintext.bytes * 2;
    $bufsize = 64 if $bufsize < 64;

    EVP_EncryptInit($ctx, $cipher, $key, ('0' x 16).encode);

    my $part = buf8.new;
    $part[$bufsize] = 0;
    my $partsize = CArray[int32].new;
    $partsize[0] = $bufsize;
    EVP_EncryptUpdate($ctx, $part, $partsize, $plaintext, $plaintext.bytes);

    my $out = $part.subbuf(0, $partsize[0]);
    $partsize[0] = $bufsize;

    EVP_EncryptFinal($ctx, $part, $partsize);
    $out ~= $part.subbuf(0, $partsize[0]);

    EVP_CIPHER_CTX_free($ctx);

    return $out;
}

# Decrypts ciphertext using aes-128-ecb
# Example: decrypt-aes($ciphertext, :key(('x' x 32).encode));
sub decrypt-aes(Blob $ciphertext, :$key) is export {
    my $cipher = EVP_aes_128_ecb();
    my $ctx = EVP_CIPHER_CTX_new();

    if $key.bytes != 16 {
        die "Key is not 128 bits";
    }

    # way bigger than needed
    my $bufsize = $ciphertext.bytes * 2;
    $bufsize = 64 if $bufsize < 64;

    EVP_DecryptInit($ctx, $cipher, $key, ('0' x 16).encode);

    my $part = buf8.new;
    $part[$bufsize] = 0;
    my $partsize = CArray[int32].new;
    $partsize[0] = $bufsize;
    EVP_DecryptUpdate($ctx, $part, $partsize, $ciphertext, $ciphertext.bytes);

    my $out = $part.subbuf(0, $partsize[0]);
    $partsize[0] = $bufsize;

    EVP_DecryptFinal($ctx, $part, $partsize);
    $out ~= $part.subbuf(0, $partsize[0]);

    EVP_CIPHER_CTX_free($ctx);

    return $out;
}
