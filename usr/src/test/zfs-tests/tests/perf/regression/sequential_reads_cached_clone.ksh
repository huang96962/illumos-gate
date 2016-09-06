#!/usr/bin/ksh

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2015 by Delphix. All rights reserved.
#

#
# Description:
# Trigger fio runs using the sequential_reads job file. The number of runs and
# data collected is determined by the PERF_* variables. See do_fio_run for
# details about these variables.
#
# The files to read from are created prior to the first fio run, and used
# for all fio runs. This test will exercise cached read performance from
# a clone filesystem. The data is initially cached in the ARC and then
# a snapshot and clone are created. All the performance runs are then
# initiated against the clone filesystem to exercise the performance of
# reads when the ARC has to create another buffer from a different dataset.
# It will also exercise the need to evict the duplicate buffer once the last
# reference on that buffer is released.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/perf/perf.shlib

function cleanup
{
	log_must $ZFS destroy $TESTFS
}

log_assert "Measure IO stats during sequential read load"
log_onexit cleanup

export TESTFS=$PERFPOOL/testfs
recreate_perfpool
log_must $ZFS create $PERF_FS_OPTS $TESTFS

# Make sure the working set can be cached in the arc. Aim for 1/2 of arc.
export TOTAL_SIZE=$(($(get_max_arc_size) / 2))

# Variables for use by fio.
if [[ -n $PERF_REGRESSION_WEEKLY ]]; then
	export PERF_RUNTIME=${PERF_RUNTIME:-$PERF_RUNTIME_WEEKLY}
	export PERF_RUNTYPE=${PERF_RUNTYPE:-'weekly'}
	export PERF_NTHREADS=${PERF_NTHREADS:-'16 64'}
	export PERF_SYNC_TYPES=${PERF_SYNC_TYPES:-'1'}
	export PERF_IOSIZES=${PERF_IOSIZES:-'64k 128k 1m'}
elif [[ -n $PERF_REGRESSION_NIGHTLY ]]; then
	export PERF_RUNTIME=${PERF_RUNTIME:-$PERF_RUNTIME_NIGHTLY}
	export PERF_RUNTYPE=${PERF_RUNTYPE:-'nightly'}
	export PERF_NTHREADS=${PERF_NTHREADS:-'64 128'}
	export PERF_SYNC_TYPES=${PERF_SYNC_TYPES:-'1'}
	export PERF_IOSIZES=${PERF_IOSIZES:-'128k 1m'}
fi

# Layout the files to be used by the read tests. Create as many files as the
# largest number of threads. An fio run with fewer threads will use a subset
# of the available files.
export NUMJOBS=$(get_max $PERF_NTHREADS)
export FILE_SIZE=$((TOTAL_SIZE / NUMJOBS))
log_must $FIO $FIO_SCRIPTS/mkfiles.fio

log_note "Creating snapshot, $TESTSNAP, of $TESTFS"
create_snapshot $TESTFS $TESTSNAP
log_note "Creating clone, $PERFPOOL/$TESTCLONE, from $TESTFS@$TESTSNAP"
create_clone $TESTFS@$TESTSNAP $PERFPOOL/$TESTCLONE

#
# Reset the TESTFS to point to the clone
#
export TESTFS=$PERFPOOL/$TESTCLONE

# Set up the scripts and output files that will log performance data.
lun_list=$(pool_to_lun_list $PERFPOOL)
log_note "Collecting backend IO stats with lun list $lun_list"
export collect_scripts=("$PERF_SCRIPTS/io.d $PERFPOOL $lun_list 1" "io"
    "$PERF_SCRIPTS/prefetch_io.d $PERFPOOL 1" "prefetch" "$VMSTAT 1" "vmstat"
    "$MPSTAT 1" "mpstat" "$IOSTAT -xcnz 1" "iostat")

log_note "Sequential cached reads from $TESTFS with $PERF_RUNTYPE settings"
do_fio_run sequential_reads.fio $FALSE $FALSE
log_pass "Measure IO stats during sequential cached read load"
