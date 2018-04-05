# Copyright 2018 Reservoir Labs

# Analyzer specifications

refine flow FIX_SBE_Flow += {
	function proc_fix_sbe_message(msg: FIX_SBE_PDU): bool
		%{
		BifEvent::generate_fix_sbe_message(connection()->bro_analyzer(), 
		                                   connection()->bro_analyzer()->Conn(),
		                                   msg->header()->len(),
		                                   msg->header()->encoding(),
		                                   msg->message()->block_length(),
		                                   msg->message()->template_id(),
		                                   msg->message()->schema_id(),
		                                   msg->message()->version());
		return true;
		%}
};

refine typeattr FIX_SBE_PDU += &let {
	proc: bool = $context.flow.proc_fix_sbe_message(this);
};

