# tor-vpin terraform

[![Build Status](https://travis-ci.org/sofwerx/tor-vpin.svg?branch=master)](https://travis-ci.org/sofwerx/tor-vpin)

This is a deployment of AWS instances that comprise the various tiers of a private tor network

# Note:

This was built using terraform 0.11.3 - if you use a newer version, please have everyone update at the same time to retain sanity.

Before running `terraform`, you will need to have a `.terraform` directory with the shared tfstate from s3.

Either run:

    make

or run this:

    terraform init --backend-config="key=tor/vpin/terraform.tfstate"

