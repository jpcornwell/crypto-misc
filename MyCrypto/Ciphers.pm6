unit module MyCrypto::Ciphers;

use MyCrypto::Misc;

# This is just a copy of OpenSSL::CryptTools simplified and tweaked to include
# AES-128-ECB and AES-128-CBC.

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

sub encrypt-aes-cbc(Blob $input, :$iv!, :$key!) is export {
    my $plaintext = add-pkcs7-padding($input);
    my $ciphertext = Buf.new;

    my @blocks = $plaintext.list.rotor(16).map: { Blob.new($^block) };

    for @blocks -> $block {
        my $block-after-xor;

        if $ciphertext.bytes {
            $block-after-xor = fixed-xor($block, $ciphertext.subbuf(*-16));
        } else {
            $block-after-xor = fixed-xor($block, $iv);
        }

        $ciphertext.push: encrypt-aes($block-after-xor, :$key).subbuf(0, 16);
    }

    return Blob.new: $ciphertext.list;
}

sub decrypt-aes-cbc(Blob $input, :$iv!, :$key!) is export {
    die '$input must be multiple of 16 bytes' if $input.bytes !%% 16;

    my @blocks = $input.list.rotor(16).map: { Blob.new($^block) };
    my $output = Buf.new;

    while @blocks.elems {
        my $block = @blocks.pop;

        my $plain = decrypt-aes(add-pkcs7-padding($block), :$key);

        my $plain-after-xor;
        if @blocks.elems {
            $plain-after-xor = fixed-xor($plain, @blocks.tail);
        } else {
            $plain-after-xor = fixed-xor($plain, $iv);
        }

        $output.unshift: $plain-after-xor;
    }

    return remove-pkcs7-padding($output);
}

sub apply-aes-ctr(Blob $input, :$nonce!, :$key!) is export {
    my $counter = 0;
    my $keystream = Buf.new;

    # Generate enough keystream to accomodate the input
    for ^ceiling($input.bytes / 16) {
        my $aes-input = Buf.new;
        $aes-input.write-uint64(0, $nonce, LittleEndian);
        $aes-input.write-uint64(8, $counter, LittleEndian);

        # Only take the first block of the encrypted output, the rest is padding
        $keystream.append: encrypt-aes($aes-input, :$key)[0..15];
        $counter++;
    }

    # Cut off extra keystream so it's length matches the input
    $keystream = Buf.new: $keystream[0 .. ($input.bytes - 1)];
    return fixed-xor($input, $keystream);
}

# Edit given ciphertext without decrypting and then re-encrypting the entire thing
sub edit-aes-ctr(Blob $cipher-blob, Int $offset, Blob $plain-blob, :$nonce!, :$key!) is export {
    my $counter = 0;
    my $keystream = Buf.new;

    # Generate enough keystream to accomodate the plaintext adjusted to given offset
    for ^ceiling(($plain-blob.bytes + $offset) / 16) {
        my $aes-input = Buf.new;
        $aes-input.write-uint64(0, $nonce, LittleEndian);
        $aes-input.write-uint64(8, $counter, LittleEndian);

        # Only take the first block of the encrypted output, the rest is padding
        $keystream.append: encrypt-aes($aes-input, :$key)[0..15];
        $counter++;
    }

    # Shift and adjust keystream to match the placement of the plaintext
    $keystream = Buf.new: $keystream[$offset ..^ ($offset + $plain-blob.bytes)];

    # Apply keystream and overwrite corresponding original ciphertext
    my $edited-cipher-blob = fixed-xor($plain-blob, $keystream);
    my $new-cipher-blob = Buf.new: $cipher-blob.list;
    $new-cipher-blob.subbuf-rw($offset, $edited-cipher-blob.bytes) = $edited-cipher-blob;
    return $new-cipher-blob;
}

