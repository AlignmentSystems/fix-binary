# Copyright 2018 Reservoir Labs

# Protocol specification

refine connection FIX_SBE_Conn += {

        function proc_fix_detected(msg: FIX_SBE_PDU): bool
        %{
                BifEvent::generate_fix_sofh_detected(bro_analyzer(), 
		                                    bro_analyzer()->Conn(), 
		                                    msg->header()->len(),
		                                    msg->header()->encoding());
                return true;
        %}
};

# SOFH Header
type FIX_SOFH_HEADER = record {
	len: uint32 &byteorder=bigendian; 
	encoding: uint16;
} &let {
	msg_length: int = len;
} &length=6, &byteorder=littleendian;

# FIX SBE message
type FIX_SBE_MESSAGE(message_length: int) = record {
	block_length: uint16;
	template_id: uint16;
	schema_id: uint16;
	version: uint16;
	body: uint8[] &length=message_length - 8; 
} &length=message_length, &byteorder=littleendian;

type FIX_SBE_PDU(is_orig: bool) = record {
	header: FIX_SOFH_HEADER &let {
                proc_detected: bool = $context.connection.proc_fix_detected(this);
        };      
	message: FIX_SBE_MESSAGE(header.msg_length);
};

