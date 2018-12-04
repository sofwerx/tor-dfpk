# tor-dfpk

[![Build Status](https://travis-ci.org/sofwerx/tor-dfpk.svg?branch=master)](https://travis-ci.org/sofwerx/tor-dfpk)

Deploying The Onion Router (TOR) infrastructure for the Digital Force Protection Kit (DFPK) on AWS.

## AWS

This project is deployed to AWS using terraform. See [terraform/README.md](terraform/README.md) for more info.

## Travis-CI

The continuous integration tool used for automated github push triggered terraform convergence runs for this project is [travis-ci](https://travis-ci.org/sofwerx/tor-dfpk)

Note: For terraform to work correctly and not deploy duplicate AWS resources if caught running in parallel, the Travis-CI concurrency needed to be limited to 1, ie:

    travis settings maximum_number_of_builds --set 1

## Clients

- [sofwerx/tor-dfpk-pizerow](https://github.com/sofwerx/tor-dfpk-pizerow) - Raspberry PI Zero W client image build for accessing a tor-dfpk deployment

