#!/bin/bash

source ./common.sh

ECODE=0
# Put query test cases here
for X in check-scripts/check*; do
	if [ ! -f "$X" ] || [ ! -x "$X" ]; then
		continue
	fi
	__info "${BLD}${YLW}$X ..........................${NC}"
	time -p ./$X
	if (($?)); then
		__err "................... $X ${BLD}${RED}failed${NC}"
		ECODE=-1
	else
		__info "................... $X ${BLD}${GRN}success${NC}"
	fi
done

exit $ECODE
