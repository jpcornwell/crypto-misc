#!/usr/bin/env perl6

use MIME::Base64;

sub hex-to-buf(Str $input) {
    return Buf.new: $input.comb.rotor(2)>>.join>>.parse-base(16);
}

sub buf-to-hex(Buf $input) {
    return $input.list.fmt('%02x', '');
}

sub base64-to-buf(Str $input) {
    return MIME::Base64.decode($input);
}

sub buf-to-base64(Buf $input) {
    return MIME::Base64.encode($input, :oneline);
}

sub fixed-xor(Buf $a, Buf $b) {
    $a.elems == $b.elems or die 'Fixed XOR requires equal length buffers';

    return $a ~^ $b;
}

# Determines if input buffer is similar to alpha ascii values.
# This basically means a-z, A-Z, and the space character.
# Cutoff can be used to tune how similar the input must be. From 0 to 100.
sub is-ascii-alpha(Buf $input, :$cutoff=95) {
    my $alpha-count = $input.list.grep(* (elem) flat(32, 65..90, 97..122)).elems;
    my $total = $input.elems;

    my $percent = ($alpha-count/$total) * 100;

    return True if $percent >= $cutoff;
    return False;
}

sub repeating-xor(Buf $input, Buf $key) {
    my $output = $input.clone;
    my $ints-from-key = flat($key.list xx *);

    for ^$output.elems -> $i {
        $output[$i] +^= $ints-from-key[$i];
    }

    return $output;
}

# TODO
# Create a function that can score how similar a given buffer is to English
# For the english and ascii scorer, allow a list of inputs to be given
#   then it would return back a list of inputs that meet the cutoff, sorted by score
#   if you want all the inputs back sorted by score, just set cutoff to zero
#   provide an optional limit, for example so you can get the 3 most likely candidates

