# tor-vpin terraform

[![Build Status](https://travis-ci.org/sofwerx/tor-vpin.svg?branch=master)](https://travis-ci.org/sofwerx/tor-vpin)

This is a deployment of AWS instances that comprise the various tiers of a private tor network

# Note:

This was built using terraform 0.11.7 - if you use a newer version, please have everyone update at the same time to retain sanity.

Before running `terraform`, you will need to have a `.terraform` directory with the shared tfstate from s3.

You can now run:

    make

which runs the script:

    ./tf.sh

which runs the command:

    terraform init --backend-config="key=tor/vpin/terraform.tfstate"

