unit module MyCrypto::RNG;

# Implementation of MT19937

my $w = 32;
my $n = 624;
my $m = 397;
my $r = 31;

my $a = 0x9908B0DF;

my $u = 11;
my $d = 0xFFFFFFFF;

my $s = 7;
my $b = 0x9D2C5680;

my $t = 15;
my $c = 0xEFC60000;

my $l = 18;

my $f = 1812433253;

my @mt = 0 xx $n - 1;
my $index = $n + 1;
my $lower-mask = (1 +< $r) - 1;
my $upper-mask = 1 +< $r;

# Initialize the generator from a seed
sub seed-mt(Int $seed) is export {
    $index = $n;
    @mt[0] = $seed;
    for 1 ..^ $n -> $i {
        @mt[$i] = $d +& ($f * (@mt[$i-1] +^ (@mt[$i-1] +> ($w-2))) + $i);
    }
}

sub extract-number is export {
    if $index >= $n {
        if $index > $n {
            die 'Generator was never seeded';
        }
        twist;
    }

    my Int $y = @mt[$index];
    $y = $y +^ (($y +> $u) +& $d);
    $y = $y +^ (($y +< $s) +& $b);
    $y = $y +^ (($y +< $t) +& $c);
    $y = $y +^  ($y +> $l);

    $index++;
    return $d +& $y;
}

sub twist is export {
    for ^$n -> $i {
        my Int $x = (@mt[$i] +& $upper-mask) + (@mt[($i+1) % $n] +& $lower-mask);
        my Int $x-a = $x +> 1;
        if $x !%% 2 {
            $x-a = $x-a +^ $a;
        }
        @mt[$i] = @mt[($i+$m) % $n] +^ $x-a;
    }
    $index = 0;
}

