#!/bin/bash

# Modify your ENV VARs so that baler programs can run
# Don't forget to add dependencies (like sos3) into the library path

BALER_PREFIX=$HOME/opt/baler
SOS_PREFIX=$HOME/opt/sos
export PATH="$BALER_PREFIX/bin:$PATH"
LD_LIBRARY_PATH="$SOS_PREFIX/lib:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH="$BALER_PREFIX/lib:$LD_LIBRARY_PATH"
export ZAP_LIBPATH=$BALER_PREFIX/lib/ovis-lib
PYTHONPATH=$BALER_PREFIX/lib/python2.7/site-packages
PYTHONPATH=$PYTHONPATH:$SOS_PREFIX/lib/python2.7/site-packages
export PYTHONPATH
export BSTORE_PLUGIN_PATH=$BALER_PREFIX/lib
