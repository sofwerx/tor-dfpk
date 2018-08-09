# tor-vpin

[![Build Status](https://travis-ci.org/sofwerx/tor-vpin.svg?branch=master)](https://travis-ci.org/sofwerx/tor-vpin)

The Onion Router (TOR) as a private Virtual Pi Network (VPiN) on AWS.

## AWS

This project is deployed to AWS using terraform. See [terraform/README.md](terraform/README.md) for more info.

## Travis-CI

The continuous integration tool used for automated github push triggered terraform convergence runs for this project is [travis-ci](https://travis-ci.org/sofwerx/tor-vpin)

Note: For terraform to work correctly and not deploy duplicate AWS resources if caught running in parallel, the Travis-CI concurrency needed to be limited to 1, ie:

    travis settings maximum_number_of_builds --set 1

## Clients

- [sofwerx/tor-vpin-pizerow](https://github.com/sofwerx/tor-vpin-pizerow) - Raspberry PI Zero W client image build for tor-vpin

