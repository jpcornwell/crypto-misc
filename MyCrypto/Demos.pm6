unit module MyCrypto::Demos;

use MyCrypto::BlackBox;
use MyCrypto::Ciphers;
use MyCrypto::Cracks;
use MyCrypto::Misc;
use MyCrypto::RNG;

# Demonstrates how one can determine if a given encryption is in ECB mode
sub determine-ecb is export {
    my $black-box = BlackBox.new;
    $black-box.init;

    for ^100 {
        $black-box.reset;

        my $input = hex-to-buf(('A' xx 64).join);
        my $output = $black-box.encrypt($input);

        my $mode = check-for-ecb-pattern($output) ?? 'ecb' !! 'cbc';

        return False if $black-box.check(:$mode) == False;
    }

    return True;
}

# Demonstrates how one can decrypt ECB ciphertext if given control of part of
# the plaintext.
sub decrypt-ecb-byte-at-a-time is export {
    my $black-box = BlackBox.new;
    $black-box.init(:ecb);
    $black-box.reset;

    my $secret = base64-to-buf(q:to/END/.split("\n").join);
      Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
      aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
      dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
      YnkK
      END

    # Determine block size
    my $block-size = 0;
    my $ciphertext-size = $black-box.encrypt($secret).bytes;
    my $expanded-size = 0;
    my $prefix = '';

    loop {
        $prefix ~= 'A';
        $expanded-size = $black-box.encrypt($prefix.encode ~ $secret).bytes;
        last if $expanded-size > $ciphertext-size;
    }

    $block-size = $expanded-size - $ciphertext-size;

    # Determine if encryption is using ECB
    $prefix = ('A' xx $block-size * 2).join.encode;
    check-for-ecb-pattern($prefix) or die 'ECB pattern not detected';

    # Decrypt secret one byte at a time
    my @message;
    my $block-count = $ciphertext-size / $block-size;
    LOOP:
    for ^$block-count -> $block-n {
        for 15 ... 0 -> $i {
            $prefix = ('A' xx $i).join.encode;
            my $selected-block = Blob.new: $black-box.encrypt($prefix ~ $secret).list.rotor($block-size)[$block-n];

            my %hash;
            for 0..255 -> $j {
                my @prefix-byte-vals = ($prefix ~ $secret).list.rotor($block-size, :partial)[$block-n];
                last LOOP if @prefix-byte-vals.elems != $block-size; # Reached the end of the message

                my $prefix-b = Blob.new: flat(@prefix-byte-vals[^($block-size-1)], $j);
                my $selected-block = Blob.new: $black-box.encrypt($prefix-b ~ $secret).list.rotor($block-size)[0];
                %hash{$j} = $selected-block;
            }

            my $char-val = %hash.pairs.grep(*.value.list eqv $selected-block.list)[0].key.Int;
            @message.push($char-val);
        }
    }

    say Blob.new(@message).decode;
}

# Same as before but harder because the controlled part of the plaintext is no
# longer at the beginning. This code could definitely be cleaned up some. Also
# this assumes the non-user-controlled prefix is random (doesn't contain ECB
# block repeats).
sub decrypt-ecb-byte-at-a-time-harder is export {
    my $black-box = BlackBox.new;
    $black-box.init(:ecb);
    $black-box.reset;

    # This prefix is sort of a pre-prefix and will always go before our user
    # controlled portion.
    my $random-prefix-size = (6..20).pick;
    my $random-prefix = Blob.new: '/dev/urandom/'.IO.open(:bin, :ro).read($random-prefix-size);

    my $secret = base64-to-buf(q:to/END/.split("\n").join);
      Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
      aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
      dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
      YnkK
      END

    # Determine block size
    my $block-size = 0;
    my $ciphertext;
    my $ciphertext-size = $black-box.encrypt($random-prefix ~ $secret).bytes;
    my $expanded-size = 0;
    my $prefix = '';

    loop {
        $prefix ~= 'A';
        $expanded-size = $black-box.encrypt($random-prefix ~ $prefix.encode ~ $secret).bytes;
        last if $expanded-size > $ciphertext-size;
    }

    $block-size = $expanded-size - $ciphertext-size;

    # Determine if encryption is using ECB
    $prefix = ('A' xx $block-size * 3).join.encode;
    check-for-ecb-pattern($random-prefix ~ $prefix) or die 'ECB pattern not detected';

    # Make offset so that we can ignore the random prefix
    my $offset = Blob.new;
    loop {
        $offset ~= 'A'.encode;
        $ciphertext = $black-box.encrypt($random-prefix ~ $offset ~ $secret);
        last if check-for-ecb-pattern($ciphertext);
    }
    my $block-offset = 1;
    my @blocks = $ciphertext.list.rotor($block-size);
    while @blocks[$block-offset] !eqv @blocks[$block-offset - 1] {
        $block-offset++;
    }
    $block-offset++;

    # Decrypt secret one byte at a time
    my @message;
    my $block-count = $ciphertext-size / $block-size;
    LOOP:
    for ^$block-count -> $block-i {
        my $block-n = $block-i + $block-offset;
        for ($block-size - 1) ... 0 -> $i {
            $prefix = ('A' xx $i).join.encode;
            my $selected-block = Blob.new: $black-box.encrypt($random-prefix ~ $offset ~ $prefix ~ $secret).list.rotor($block-size)[$block-n];

            my %hash;
            for 0..255 -> $j {
                my @prefix-byte-vals = ($random-prefix ~ $offset ~ $prefix ~ $secret).list.rotor($block-size, :partial)[$block-n];
                last LOOP if @prefix-byte-vals.elems != $block-size; # Reached the end of the message

                my $prefix-b = Blob.new: flat(@prefix-byte-vals[^($block-size-1)], $j);
                my $selected-block = Blob.new: $black-box.encrypt($random-prefix ~ $offset ~ $prefix-b ~ $secret).list.rotor($block-size)[$block-offset];
                %hash{$j} = $selected-block;
            }

            my $char-val = %hash.pairs.grep(*.value.list eqv $selected-block.list)[0].key.Int;
            @message.push($char-val);
        }
    }

    say Blob.new(@message).decode;
}

# Demonstrates ECB "cut and paste"
sub ecb-cut-and-paste is export {
    my $black-box = BlackBox.new;
    $black-box.init(:ecb);
    $black-box.reset;

    class Cookie {
        has Str $.email;
        has Int $.uid;
        has Str $.role;

        method tokenize {
            return "email=$!email&uid=$!uid&role=$!role";
        }
    }

    sub parse-token(Str $token) {
        my $email = '';
        my $uid = -1;
        my $role = '';

        my @params = $token.split('&');

        for @params -> $param {
            my ($key, $val) = $param.split('=');
            $email = $val if $key eq 'email';
            $uid = $val.Int if $key eq 'uid';
            $role = $val if $key eq 'role';
        }

        die 'Invalid email' if $email eq '';
        die 'invalid uid' if $uid == -1;
        die 'invalid role' if $role eq '';

        return Cookie.new: :$email, :$uid, :$role;
    }

    sub profile-for(Str $email) {
        my $cookie = Cookie.new: :$email, uid => 10, role => 'user';
        my $encrypted-token = $black-box.encrypt($cookie.tokenize.encode);
        return $encrypted-token;
    }

    sub check-token-for-admin(Blob $encrypted-token) {
        my $token = $black-box.decrypt($encrypted-token).decode;
        say "Checking token: $token";
        my $cookie = parse-token($token);
        return True if $cookie.role eq 'admin';
        return False;
    }

    my $payload = "ZZZZZZZZZZadmin\c[11]\c[11]\c[11]\c[11]\c[11]\c[11]\c[11]\c[11]\c[11]\c[11]\c[11]";
    my $special-token = profile-for($payload);
    my @admin-byte-vals = $special-token.list.rotor(16)[1];

    my $attacker-token = profile-for('attacker_foobarbar@domain.com');
    my $result = check-token-for-admin($attacker-token);
    $result == False or die 'Unmodified token should not have admin role';

    my @token-start-vals = $attacker-token.list.rotor(16)[^3].flat;
    my $modified-attacker-token = Blob.new: flat(@token-start-vals, @admin-byte-vals);

    $result = check-token-for-admin($modified-attacker-token);
    $result == True or die 'Modified token should have admin role';
}

# Demonstrates how to do a CBC bitflipping attack
sub cbc-bit-flip is export {
    my $black-box = BlackBox.new;
    $black-box.init(:cbc);
    $black-box.reset;

    sub create-token(Str $input) {
        my $prefix = 'comment1=cooking MCs;userdata='.encode;
        my $suffix = ';comment2= like a pound of bacon'.encode;

        return $black-box.encrypt($prefix ~ $input.encode ~ $suffix);
    }

    sub is-token-admin(Blob $input) {
        my $token = $black-box.decrypt($input).decode('utf8-c8');

        return True if $token.contains(';admin=true;');

        return False;
    }

    my $encrypted-token = create-token('yyaaaaaaaaaaaaaaaaXXXXXXXXXXXXXXXX');
    is-token-admin($encrypted-token) == False or die 'Unmodified token should not be admin';

    # Modify 3rd block (which will bit flip the 4th block)
    my $desired-payload = ';admin=true;;;;;'.encode;
    my @blocks = $encrypted-token.list.rotor(16);
    my $foo = fixed-xor('XXXXXXXXXXXXXXXX'.encode, $desired-payload);
    @blocks[2] = fixed-xor(Buf.new(@blocks[2]), $foo).list;
    my $modified-token = Blob.new: @blocks.join(' ').split(' ')>>.Int;

    is-token-admin($modified-token) == True or die 'Modified token should be admin';
}

# Demonstrates exploit using CBC padding oracle
sub cbc-padding-oracle-exploit is export {
    my $key = rand-blob(16);
    my $iv = rand-blob(16);

    sub get-ciphertext-blob {
        my $message = q:to/END/.split("\n").pick;
            MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
            MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
            MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
            MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
            MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
            MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
            MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
            MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
            MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
            MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
        END
        my $plaintext-blob = base64-to-buf($message);

        return encrypt-aes-cbc($plaintext-blob, :$iv, :$key);
    }

    # Returns True if padding is valid, False otherwise
    sub padding-oracle($ciphertext-blob) {
        try {
            decrypt-aes-cbc($ciphertext-blob, :$iv, :$key);
            return True;
        }
        return False;
    }

    my $cipher-blob = get-ciphertext-blob();
    my $temp-buf = Buf.new: $cipher-blob.list;
    my $plain-buf = Buf.new;

    my $block-count = $temp-buf.bytes / 16;
    # Start at the last block and work towards the beginning (ignoring the first block)
    for ($block-count - 1) ... 1 -> $current-block {
        my $current-block-index = $current-block * 16;
        my $previous-block-index = $current-block-index - 16;

        # Make temp copy of previous block (because we will be editing it to bit flip current block)
        my $block-copy = Buf.new: $temp-buf[$previous-block-index .. $previous-block-index + 15];

        # For some reason subbuf is timing out and killing the program
        # my $block-copy = $temp-buf.subbuf($previous-block-index, 16);
        
        # Go byte by byte starting at the end
        for 15 ... 0 -> $byte-offset {
            # Figure out padding value to use
            my $padding-val = 16 - $byte-offset;
            
            # Try to break any padding that already exists. (Success is not guaranteed, but most likely will work.)
            # This is only necessary when determining the last byte. After that, we control the last byte,
            #     which subsequently controls the padding value.
            if $byte-offset == 15 {
		$temp-buf[$previous-block-index + 14] +^= 2;
            }
            
            # Adjust bytes that come after byte offset to padding value
            for ($byte-offset + 1) .. 15 -> $second-byte-offset {
                $temp-buf[$previous-block-index + $second-byte-offset] +^= $plain-buf[$current-block-index + $second-byte-offset] +^ $padding-val;
            }
            
            # Loop through bit flipping the byte offset until padding-oracle returns True
            my $temp-val = 0;
            loop {
                $temp-buf[$previous-block-index + $byte-offset] = $temp-val;
                last if padding-oracle($temp-buf);
                $temp-val++;
                die 'Infinite loop' if $temp-val > 255;
            }
            
            # Determine actual value at byte-offset and set in plain-buf
            $plain-buf[$current-block-index + $byte-offset] = $temp-val +^ $padding-val +^ $block-copy[$byte-offset];

            # Restore the previous block value using the block copy made earlier
            $temp-buf[$previous-block-index .. ($previous-block-index + 15)] = $block-copy.list;
        }

        # Cut off the last block
        $temp-buf = Buf.new: $temp-buf[0 .. ($current-block-index - 1)];
    }

    # Remove first block which we are not able to crack
    $plain-buf = Buf.new: $plain-buf[16 .. *];
    
    my $message = remove-pkcs7-padding($plain-buf).decode;
    say "Plain buf: $plain-buf.list()";
    say "Message: $message";
}

sub break-fixed-nonce-ctr is export {
    my $nonce = 0;
    my $key = 'YELLOW SUBMARINE'.encode;
    my $keystream = Buf.new;

    my @plain-blobs = 'MyCrypto/data/plaintext-data-base64.txt'.IO.lines>>.&base64-to-buf;
    my @cipher-blobs = @plain-blobs>>.&apply-aes-ctr(:$nonce, :$key);

    my $min-length = min(@cipher-blobs>>.bytes);
    @cipher-blobs .= map: *.subbuf(^$min-length);

    for ^$min-length -> $index {
        my $section = Buf.new: @cipher-blobs>>[$index];
        $keystream.append: crack-single-xor($section)<key>;
    }

    my @cracked-blobs = @cipher-blobs>>.&fixed-xor($keystream);
    .say for @cracked-blobs>>.decode;

    say "\n-------------------------------------------------------\n";

    .say for @plain-blobs>>.decode;
}

# Demonstrates cracking an RNG seed based on Unix timestamp
sub crack-mt19937-seed is export {
    my $wait-time = (40..100).pick;
    sleep $wait-time;
    my $seed = DateTime.new(now).posix;
    my $mt = MtGenerator.new;
    $mt.seed($seed);
    my $output = $mt.extract-number;
    say "Random number generated: $output";
    $wait-time = (40..100).pick;
    sleep $wait-time;

    my $current = DateTime.new(now).posix;
    my $begin-try = $current - 2000;

    for $begin-try .. $current -> $i {
        $mt.seed($i);
        if $mt.extract-number() == $output {
            my $guessed-seed = $i;
            $guessed-seed == $seed or die 'Incorrect guessed seed';
            say "Seed value is $guessed-seed";
            last;
        }
    }
}

# Demonstrate cloning an RNG output sequence by recreating its internal state
sub clone-mt19937 is export {
    my $mt = MtGenerator.new;
    $mt.seed: 42;

    my @recreated-state;
    @recreated-state.push: mt-untemper $mt.extract-number for ^624;

    my $cloned-mt = MtGenerator.new;
    $cloned-mt.set-state: @recreated-state;

    die 'Cloned output is not the same!' if $mt.extract-number != $cloned-mt.extract-number for ^10_000;
    say 'Success!';
}

# Demonstrate attack on 'random access read/write' AES CTR
sub attack-rand-access-aes-ctr is export {
    my $plain-blob = 'MyCrypto/data/plaintext-data-base64.txt'.IO.lines[0].&base64-to-buf;

    my $nonce = 0;
    my $key = rand-blob 16;

    my $cipher-blob = apply-aes-ctr($plain-blob, :$nonce, :$key);
    
    # By overwriting the entire message with 'zero bits' we can get back the keystream
    my $keystream = edit-aes-ctr($cipher-blob, 0, Buf.new(0 xx $cipher-blob.bytes), :$nonce, :$key);

    my $derived-plain-blob = fixed-xor($cipher-blob, $keystream);
    say 'Plain:   ', $plain-blob.decode;
    say 'Derived: ', $derived-plain-blob.decode;
    die 'Unable to derive original plaintext' if $plain-blob.decode ne $derived-plain-blob.decode;

    say 'Success!';
}

