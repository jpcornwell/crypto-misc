unit module MyCrypto::Demos;

use MyCrypto::BlackBox;
use MyCrypto::Misc;

# Demonstrates how one can determine if a given encryption is in ECB mode
sub determine-ecb is export {
    my $black-box = BlackBox.new;

    for ^100 {
        $black-box.set;

        my $input = hex-to-buf(('A' xx 64).join);
        my $output = $black-box.encrypt($input);

        my $mode = check-for-ecb-pattern($output) ?? 'ecb' !! 'cbc';

        return False if $black-box.check(:$mode) == False;
    }

    return True;
}

