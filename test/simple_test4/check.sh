#!/bin/bash

source ./common.sh

# Put query test cases here
for X in check-scripts/check*; do
	if [ ! -f "$X" ] || [ ! -x "$X" ]; then
		continue
	fi
	__info "${BLD}${YLW}$X ..........................${NC}"
	time -p ./$X
	if (($?)); then
		__err "................... $X ${BLD}${RED}failed${NC}"
	else
		__info "................... $X ${BLD}${GRN}success${NC}"
	fi
done
