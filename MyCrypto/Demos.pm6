unit module MyCrypto::Demos;

use MyCrypto::BlackBox;
use MyCrypto::Misc;

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
