# Copyright 2018 Reservoir Labs

# Analyzer for Financial Information eXchange (Binary SBE)
#  - fix-protocol.pac: describes the FIX protocol messages
#  - fix-analyzer.pac: describes the FIX analyzer code

%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

# Analyzer definition
analyzer FIX_SOFH withcontext {
	connection: FIX_SBE_Conn;
	flow:       FIX_SBE_Flow;
};

# Connection definition
connection FIX_SBE_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = FIX_SBE_Flow(true);
	downflow = FIX_SBE_Flow(false);
};

%include fix_sbe-protocol.pac

# Flow definition
flow FIX_SBE_Flow(is_orig: bool) {
	flowunit = FIX_SBE_PDU(is_orig) withcontext(connection, this);
};

%include fix_sbe-analyzer.pac
