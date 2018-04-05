// Copyright 2018 Reservoir Labs

#ifndef ANALYZER_PROTOCOL_FIX_SBE_FIX_SBE_H
#define ANALYZER_PROTOCOL_FIX_SBE_FIX_SBE_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "fix_sbe_pac.h"

namespace analyzer { namespace FIX_SOFH {

class FIX_SBE_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	FIX_SBE_Analyzer(Connection* conn);
	virtual ~FIX_SBE_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new FIX_SBE_Analyzer(conn); }

protected:
	binpac::FIX_SOFH::FIX_SBE_Conn* interp;
	
	bool had_gap;
	
};

} } // namespace analyzer::* 

#endif
