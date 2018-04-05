# Copyright 2018 Reservoir Labs

##! Implements base functionality for FIX_SBE analysis.
##! Generates the fix_sbe.log file.

module Fix_sbe;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time               &log;            ## Timestamp for when the event happened.
		uid: string            &log;            ## Unique ID for the connection.  
		id: conn_id            &log;            ## The connection's 4-tuple of endpoint addresses/ports.
		rec_type: string       &log &optional;  ## Message type
		frame_length: count    &log;            ## Length of the frame 
		frame_encoding: string &log;            ## Encoding of the frame
		block_length: count    &log &optional;  ## Length of the block
		template_id: count     &log &optional;  ## Template ID
		schema_id: count       &log &optional;  ## Schema ID
		schema_version: count  &log &optional;  ## Schema version
		note: string           &log &optional;  ## Used to write additional notes
		# Other internal per-context state not to be logged
		analyzer_id: count     &optional;       ## The ID of the FIX analyzer processing this connection
		disabled_aids: set[count] &optional;    ##  Track if analyzer was disabled to avoid disabling it again
	};

	## Event that can be handled to access the FIX_SBE record as it is sent on
	## to the loggin framework.
	global log_fix_sbe: event(rec: Info);

	#
	# Encodings
	#
	global sbe_encodings: table[count] of string = {
		# See "Simple Open Framing Header Technical 
		# Specification" section 2.1.2  
		[57435] = "FIX_SBE_Big_Endian", 
		[20715] = "FIX_SBE_Little_Endian",
		[71]    = "FIX_GPB",
		[165]   = "FIX_ASN.1_PER",
		[421]   = "FIX_ASN.1_BER",
		[677]   = "FIX_ASN.1_OER",
		[240]   = "FIXTV",
		[241]   = "FIXML",
		[250]   = "FIX_FAST",
		[245]   = "FIX_JSON",
		[251]   = "FIX_BSON",
	} &redef;

	#
	# Templates
	#

	## General schema type to map template IDs onto human readable descriptions
	type schema: table[count] of string; 

	## Schema ID 2748 xmlns:sbe="http://fixprotocol.io/2016/sbe"
	global schema_2748: schema = {
		[1]  = "Negotiate",
		[2]  = "NegotiationResponse",
		[3]  = "NegotiationReject",
		[4]  = "Topic",
		[5]  = "Establish",
		[6]  = "EstablishmentAck",
		[7]  = "EstablishmentReject",
		[8]  = "Sequence",
		[9]  = "Context",
		[10] = "UnsequencedHeartbeat",
		[11] = "Undefined",
		[12] = "Retransmission",
		[13] = "RestransmitReject",
		[14] = "Terminate",
		[15] = "FinishedSending",
		[16] = "FinishedReceiving",
		[17] = "Applied",
		[18] = "NotApplied",
	} &redef;

	## Schema ID 2 xmlns:sbe="http://www.fixprotocol.org/ns/simple/1.0" 
	global schema_2: schema = {
		[1] = "EnterOrder",
		[2] = "Accepted",
	} &redef;

	# Add here other schema definitions

	## Map between template IDs and templates
	global templates: table[count] of schema = {
		[2] = schema_2, 
		[2748] = schema_2748, 
		# Add here other schema mappings
	} &redef;

}

# Add a fix sbe context to the connection record
redef record connection += {
        fix_sbe: Info &optional;
};


# There is no IANA standard port number for the FIX protocol.
# While setting this variable is not mandatory since we rely on DPD to attach the FIX
# analyzer to a connection, if in your specific configuration you have a
# port number associated with your FIX service, you can add it here. This will allow
# you to detect misuses of this port number. Make sure you also enable the call to
# Analyzer::register_for_ports in bro_init.
# Example: 
# const ports : set[port] = { 1234/tcp, 5678/tcp };
const ports : set[port] = { };
redef likely_server_ports += { ports };

# Set this flag to false if you need to enhance your chances 
# of detecting FIX traffic on already initiated connections. This can help detect
# FIX traffic on very long lived connections. (default value: T)
# Note: setting this to false can have a negative impact on performance.
redef dpd_match_only_beginning = T;

# Increase this buffer in order to increase the amount of past data 
# the FIX analyzer will be able to parse upon attaching itself to
# a connection. This rarely needs to be increased. (default value: 1024)
# Note: increasing this value can have a negative impact on performance.
redef dpd_buffer_size = 1024;

event bro_init() &priority=5
	{
	Log::create_stream(Fix_sbe::LOG, [$columns=Info, $ev=log_fix_sbe, $path="fix_sbe"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_FIX_SOFH, ports);
	}

event fix_sofh_detected(c: connection,
                       length: count,
                       encoding: count)
        {
        # The message first bytes (up to the SOFH header) were correctly
        # parsed. Consider this a connection detected as FIX. Notice
        # that this does not mean the message has been validated
        # as being fully FIX compliant. If the message is not compliant,
        # a FIX record in fix.log will be reported of type VALIDATION_FAILED.
        local service: string;

	if (encoding !in sbe_encodings) 
		service = "UnknownEncoding"; 
	else 
		service = sbe_encodings[encoding];

        add c$service[service];
        }

event fix_sbe_message(c: connection,
                      frame_length: count,
                      frame_encoding: count,
                      block_length: count,
                      template_id: count,
                      schema_id: count,
                      schema_version: count)
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$frame_length = frame_length;
	if (frame_encoding !in sbe_encodings) 
		info$frame_encoding = "UnknownEncoding"; 
	else 
		info$frame_encoding = sbe_encodings[frame_encoding];
	info$block_length = block_length;
	info$template_id = template_id;
	info$schema_id = schema_id;
	info$schema_version = schema_version;
	if (info$schema_id !in templates)
		info$rec_type = "UnknownSchemaID";
	else if (info$template_id !in templates[info$schema_id])
		info$rec_type = "UnknownTemplateID";
	else
		info$rec_type = templates[info$schema_id][info$template_id];
	Log::write(Fix_sbe::LOG, info);

        # Since we have already validated that one FIX message in this connection
        # complies, we can disable the analyzer for this connection
        # if the analyzer ID was already populated by protocol_confirmation()
        if (c?$fix_sbe && c$fix_sbe?$analyzer_id && (c$fix_sbe$analyzer_id !in c$fix_sbe$disabled_aids))
                {
                disable_analyzer(c$id, c$fix_sbe$analyzer_id);
                add c$fix_sbe$disabled_aids[c$fix_sbe$analyzer_id];
                }

	}

function set_session(c: connection)
        {
        if (!c?$fix_sbe)
                {
                # Allocate a new fix sbe record
                local info: Fix_sbe::Info;
                c$fix_sbe = info;
                c$fix_sbe$disabled_aids = set();
                }
        }

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
        {
        if (atype == Analyzer::ANALYZER_FIX_SOFH)
                {
                set_session(c);
                c$fix_sbe$analyzer_id = aid;
                }
        }

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string)
        {
        if (atype != Analyzer::ANALYZER_FIX_SOFH)
                return;
        # Set context if it has not been set yet
        set_session(c);
        # Don't disable the analyzer if it was already disabled
        if (aid in c$fix_sbe$disabled_aids)
                return;
        # A connection detected as FIX has a protocol non-compliant message, 
	# report it and disable the analyzer
        local info: Info;
        info$ts = network_time();
        info$uid = c$uid;
        info$id = c$id;
        info$rec_type = "ValidationFailed";
        # Generic note 
        local fix_reason = "Failed to parse non-compliant FIX SBE message";
        # Try to get a more specific note by pasing the reason parameter and sanitizing it
        if ("expected pattern" in reason) {
                fix_reason = fmt("Expected pattern%s", split_string(reason, /expected pattern/)[1]);
	        if ("actual data" in reason)
        	        fix_reason =  sub(fix_reason, /actual data/, " Actual data");
	}
	else if("out_of_bound:" in reason) 
                fix_reason = fmt("Out of bound:%s", split_string(reason, /out_of_bound:/)[1]);
	
        info$note = fix_reason;
        Log::write(Fix_sbe::LOG, info);

        # Disable analyzer
        disable_analyzer(c$id, aid);
        add c$fix_sbe$disabled_aids[aid];
        }

