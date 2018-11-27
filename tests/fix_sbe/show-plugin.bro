# @TEST-EXEC: bro -NN RLABS::FIX_SBE |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
