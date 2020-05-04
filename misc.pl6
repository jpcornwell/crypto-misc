#!/usr/bin/env perl6

use MIME::Base64;

sub hex-to-buf($input) {
    return Buf.new: $input.comb.rotor(2)>>.join>>.parse-base(16);
}

sub buf-to-hex($input) {
    return $input.list.fmt('%02x', '');
}

sub base64-to-buf($input) {
    return MIME::Base64.decode($input);
}

sub buf-to-base64($input) {
    return MIME::Base64.encode($input, :oneline);
}

