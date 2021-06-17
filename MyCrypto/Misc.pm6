unit module MyCrypto::Misc;

use MIME::Base64;

sub hex-to-buf(Str $input) is export {
    return Buf.new: $input.comb.rotor(2)>>.join>>.parse-base(16);
}

sub buf-to-hex(Blob $input) is export {
    return $input.list.fmt('%02x', '');
}

sub base64-to-buf(Str $input) is export {
    return MIME::Base64.decode($input);
}

sub buf-to-base64(Blob $input) is export {
    return MIME::Base64.encode($input, :oneline);
}

sub fixed-xor(Blob $a, Blob $b) is export {
    $a.elems == $b.elems or die 'Fixed XOR requires equal length buffers';

    return $a ~^ $b;
}

# Determines if input binary data is similar to alpha ascii values.
# This basically means a-z, A-Z, and the space character.
# Cutoff can be used to tune how similar the input must be. From 0 to 100.
sub is-ascii-alpha(Blob $input, :$cutoff=95) is export {
    my $alpha-count = $input.list.grep(* (elem) flat(32, 65..90, 97..122)).elems;
    my $total = $input.elems;

    my $percent = ($alpha-count/$total) * 100;

    return True if $percent >= $cutoff;
    return False;
}

sub repeating-xor(Blob $input, Blob $key) is export {
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

sub hamming-distance(Blob $a, Blob $b) is export {
    $a.elems == $b.elems or die 'Hamming distance requires equal length buffers';

    return fixed-xor($a, $b).list>>.base(2)>>.comb('1').reduce(&[+]);
}

# Checks if the input binary data has any repeated 16 byte blocks
sub check-for-ecb-pattern(Blob $input) is export {
    my @blocks = $input.list.rotor(16).map: { Blob.new($^block) };
    my $counts = bag @blocks;

    return True if $_ > 1 for $counts.values;

    return False;
}

sub add-pkcs7-padding(Blob $input) is export {
    my $output = Buf.new: $input.list;

    my $padding-length = 16 - ($output.bytes % 16);
    my $padding = Buf.new: $padding-length xx $padding-length;

    $output.push($padding);
    return Blob.new: $output.list;
}

sub remove-pkcs7-padding(Blob $input) is export {
    my $padding-length = $input.list.tail;

    my @padding-vals = $input.list[(* - $padding-length) .. *];

    for @padding-vals -> $val {
        die 'Invalid padding' if $val != $padding-length;
    }

    return Blob.new: $input[0 ..^ (* - $padding-length)];
}
