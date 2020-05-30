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

