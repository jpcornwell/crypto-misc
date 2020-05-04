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

