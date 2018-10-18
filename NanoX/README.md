# NanoX-miner
NanoX Miner for AMD GPUs

If you get an error about clCreateBuffer - lower your rawintensity. See the example config for details.

Generally, you want to raise rawintensity as high as it will go without error - but remember, 2MiB of GPU RAM is needed for every work-item.

The GPU fan, powertune, and clock setting options are accepted, as the configuration routine was ripped from my own full-custom miner, but they do nothing.
