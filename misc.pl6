#!/usr/bin/env perl6

use MIME::Base64;

use lib '.';
use OpenSSL::Tweaked;

sub hex-to-buf(Str $input) {
    return Buf.new: $input.comb.rotor(2)>>.join>>.parse-base(16);
}

sub buf-to-hex(Blob $input) {
    return $input.list.fmt('%02x', '');
}

sub base64-to-buf(Str $input) {
    return MIME::Base64.decode($input);
}

sub buf-to-base64(Blob $input) {
    return MIME::Base64.encode($input, :oneline);
}

sub fixed-xor(Blob $a, Blob $b) {
    $a.elems == $b.elems or die 'Fixed XOR requires equal length buffers';

    return $a ~^ $b;
}

# Determines if input binary data is similar to alpha ascii values.
# This basically means a-z, A-Z, and the space character.
# Cutoff can be used to tune how similar the input must be. From 0 to 100.
sub is-ascii-alpha(Blob $input, :$cutoff=95) {
    my $alpha-count = $input.list.grep(* (elem) flat(32, 65..90, 97..122)).elems;
    my $total = $input.elems;

    my $percent = ($alpha-count/$total) * 100;

    return True if $percent >= $cutoff;
    return False;
}

sub repeating-xor(Blob $input, Blob $key) {
    my $output = Buf.new: $input;
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
# English scorer can also use a dictionary of words to help accuracy

sub hamming-distance(Blob $a, Blob $b) {
    $a.elems == $b.elems or die 'Hamming distance requires equal length buffers';

    return fixed-xor($a, $b).list>>.base(2)>>.comb('1').reduce(&[+]);
}

# Given binary input, try to guess most likely keysizes for repeating key XOR.
# Will consider keysizes from $min to $max, and will return $limit most likely.
# TODO
# Investigate ways to make this more accurate
# Test this against numerous cases and see how accurate it is
sub guess-keysize(Blob $input, Int :$min=2, Int :$max=40, Int :$limit=3) {
    my %scores;

    for $min..$max -> $keysize {
        my @two-block-lists = $input.rotor($keysize * 2);

        last if @two-block-lists.elems == 0;
        %scores{$keysize} = 0;
        for @two-block-lists -> @two-block-list {
            my @blocks = @two-block-list.rotor($keysize);
            my $block-a = Blob.new: @blocks[0];
            my $block-b = Blob.new: @blocks[1];
            %scores{$keysize} += hamming-distance($block-a, $block-b) / $keysize;
        }
        %scores{$keysize} /= @two-block-lists.elems;
    }

    my @candidates = %scores.sort(*.value).head($limit)>>.key;

    return @candidates[0] if @candidates.elems == 1;
    return @candidates;
}

sub crack-single-xor(Blob $input) {
    my $message;
    my $key;
    for ^255 -> $i {
        $key = $i;
        $message = repeating-xor($input, Blob.new: $key);
        last if is-ascii-alpha($message, :80cutoff);
    }

    return { 'message' => $message, 'key' => $key };
}

# TODO
# Improve the logic
#   Should allow trying multiple keysize guesses
sub crack-repeating-xor(Blob $input) {
    my $keysize = guess-keysize($input, :limit(1));

    my @transposed;
    for ^$keysize -> $i {
        my $block = Blob.new: $input.list[$i, $i + $keysize ... *];
        @transposed.push: $block;
    }

    my $key = Buf.new;
    for @transposed -> $i {
        $key.push(crack-single-xor($i)<key>);
    }

    my $message = repeating-xor($input, $key);
    return { 'message' => $message, 'key' => $key };
}

# Checks if the input binary data has any repeated 16 byte blocks
sub check-for-ecb-pattern(Blob $input) {
    my @blocks = $input.list.rotor(16).map: { Blob.new($^block) };
    my $counts = bag @blocks;

    return True if $_ > 1 for $counts.values;

    return False;
}

sub add-pkcs7-padding(Buf $input) {
    my $output = $input.clone;

    my $padding-length = 16 - ($output.bytes % 16);
    my $padding = Buf.new: $padding-length xx $padding-length;

    $output.push($padding);
    return $output;
}

