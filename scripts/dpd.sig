# Copyright 2018 Reservoir Labs

# DPD signature to attach the FIX SBE analyzer to TCP connections

signature dpd_fix_sofh {
        ip-proto == tcp

	#
	# SOFH Frame Header: 
	# (See "Simple Open Framing Header Technical Specification" Section 2.1.2)
	#--------------------------------------------------------------------
	#   - 32 bit frame length field   = .... 
	#   - 16 bit encoding type        = \x5b\xe0 => FIX SBE Big Endian
	#                                 = \xeb\x50 => FIX SBE Little Endian
	#                                 = \x47\x00 => FIX GPB
	#                                 = \xA5\x00 => FIX ASN.1 PER
	#                                 = \xA5\x01 => FIX ASN.1 BER
	#                                 = \xA5\x02 => FIX ASN.1 OER
	#                                 = \xF0\x00 => FIXTV
	#                                 = \xF1\x00 => FIXML
	#                                 = \xFA\x00 => FIX FAST
	#                                 = \xF5\x00 => FIX JSON
	#                                 = \xFB\x00 => FIX BSON
	# Message header:
	# (See "Simple Binary Encoding Technical Specification" Section 3)
	#--------------------------------------------------------------------
	#
	# Note: support more schemas by adding their IDs below
	#
	#   - 16 bit header length field  = ..
	#   - 16 bit template ID          = ..  
	#   - 16 bit schema ID            = \xbc\x0a => 2748 (xmlns:sbe="http://fixprotocol.io/2016/sbe")
	#                                 = \x02\x00 => 2    (xmlns:sbe="http://www.fixprotocol.org/ns/simple/1.0")
	#   - 16 bit version ID           = .. 
	#
        # This is a very general signature to catch any SOFH header.
        # It is possible that other packets at random will match the same 16-bits of SOFH.
        # In that case, we'll say this was FIX, but then later on it will have a protocol validation
        # failure. This can be made more specific by only matching on SBE with the downside of missing
        # any of the other SOFH types.
        #
        # SBE specific dpd
        # payload /^....(\x5b\xe0|\xeb\x50|\x47\x00|\xA5\x00|\xA5\x01|\xA5\x02|\xF0\x00|\xF1\x00|\xFA\x00|\xF5\x00|\xFB\x00)....(\xbc\x0a|\x02\x00)../

        payload /^....(\x5b\xe0|\xeb\x50|\x47\x00|\xA5\x00|\xA5\x01|\xA5\x02|\xF0\x00|\xF1\x00|\xFA\x00|\xF5\x00|\xFB\x00)/
	
        enable "fix_sofh"
}

