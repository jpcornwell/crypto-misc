unit module MyCrypto::Cracks;

use MyCrypto::Misc;

# Given binary input, try to guess most likely keysizes for repeating key XOR.
# Will consider keysizes from $min to $max, and will return $limit most likely.
# TODO
# Investigate ways to make this more accurate
# Test this against numerous cases and see how accurate it is
sub guess-keysize(Blob $input, Int :$min=2, Int :$max=40, Int :$limit=3) is export {
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

sub crack-single-xor(Blob $input) is export {
    my $message;
    my $key;

    $key = max(^256, :by({ ascii-alpha-score(repeating-xor($input, Blob.new: $_)) }));

    return { 'message' => $message, 'key' => $key };
}

# TODO
# Improve the logic
#   Should allow trying multiple keysize guesses
sub crack-repeating-xor(Blob $input) is export {
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

