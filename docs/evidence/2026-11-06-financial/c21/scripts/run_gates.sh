#!/bin/bash
E=$1; P=$2; B=/var/tmp/c21/baseline; SRC=/var/tmp/c21/src-current
cd $B
python3 c21_gate_wrapper.py $B/lab_c19_dashboard.py $E $P $SRC > $B/dashboard.log 2>&1; echo "EXIT $?" >> $B/dashboard.log
python3 c21_gate_wrapper.py $B/lab_thursday.py $E $P $SRC > $B/thursday.log 2>&1; echo "EXIT $?" >> $B/thursday.log
