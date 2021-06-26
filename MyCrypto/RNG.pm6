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

my $lower-mask = (1 +< $r) - 1;
my $upper-mask = 1 +< $r;

class MtGenerator is export {
    has @!mt = 0 xx $n;
    has $!index = $n + 1;

    # Initialize the generator from a seed
    method seed(Int $seed) {
        $!index = $n;
        @!mt[0] = $seed;
        for 1 ..^ $n -> $i {
            @!mt[$i] = $d +& ($f * (@!mt[$i-1] +^ (@!mt[$i-1] +> ($w-2))) + $i);
        }
    }

    method extract-number {
        if $!index >= $n {
            if $!index > $n {
                die 'Generator was never seeded';
            }
            self.twist;
        }

        my Int $y = @!mt[$!index];
        $y = $y +^ (($y +> $u) +& $d);
        $y = $y +^ (($y +< $s) +& $b);
        $y = $y +^ (($y +< $t) +& $c);
        $y = $y +^  ($y +> $l);

        $!index++;
        return $d +& $y;
    }

    method twist {
        for ^$n -> $i {
            my Int $x = (@!mt[$i] +& $upper-mask) + (@!mt[($i+1) % $n] +& $lower-mask);
            my Int $x-a = $x +> 1;
            if $x !%% 2 {
                $x-a = $x-a +^ $a;
            }
            @!mt[$i] = @!mt[($i+$m) % $n] +^ $x-a;
        }
        $!index = 0;
    }

    method set-state(@input) {
        @!mt = @input;
        $!index = $n;
    }
}

# For the Mersenne Twister, when a number is pulled from the internal state it goes through a process
# called tempering. This function does the reverse so that given an MT output, it can determine
# the value that was pulled directly from the MT state. (Do this enough times and you can completely
# recreate the MT internal state and then compute all future values of the output sequence.)
sub mt-untemper(uint32 $input) is export {
    my Int $y = $input;
    my Int $a;
    my Int $mask;

    $mask = ($d +< ($w - $l)) +& $d;
    $a = $y +& $mask;
    until $mask == 0 {
        $mask +>= $l;
        $a +|= (($a +> $l) +^ $y) +& $mask;
    }
    $y = $a;

    $mask = $d +> ($w - $t);
    $a = $y +& $mask;
    until $mask == 0 {
        $mask = ($mask +< $t) +& $d;
        $a +|= ((($a +< $t) +& $c) +^ $y) +& $mask;
    }
    $y = $a;

    $mask = $d +> ($w - $s);
    $a = $y +& $mask;
    until $mask == 0 {
        $mask = ($mask +< $s) +& $d;
        $a +|= ((($a +< $s) +& $b) +^ $y) +& $mask;
    }
    $y = $a;

    $mask = ($d +< ($w - $u)) +& $d;
    $a = $y +& $mask;
    until $mask == 0 {
        $mask +>= $u;
        $a +|= (($a +> $u) +^ $y) +& $mask;
    }
    $y = $a;

    return $y;
}

