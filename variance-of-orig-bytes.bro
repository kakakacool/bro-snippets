##! Look for low variance in the number of bytes being sent 
##! by connection originators.  Sometimes this can indicate
##! hosts behaving "strangely".

module LowVariance;

export {
	redef enum Notice::Type += {
		In_Orig_Bytes
	};
}

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="end_of_conn", $apply=set(SumStats::VARIANCE, SumStats::SUM));
	SumStats::create([$name="variance_of_orig_bytes",
	                  $epoch=5min,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["end_of_conn"];
	                  	if ( r$num > 100 )
	                  		return 1.0 - r$variance;
	                  	else 
	                  		return 0.0;
	                  	},
	                  $threshold=0.9,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["end_of_conn"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local message = fmt("%s did %d connections with %.2f variance on orig bytes in %s", key$host, r$num, r$variance, dur);
	                  	NOTICE([$note=In_Orig_Bytes,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event connection_state_remove(c: connection)
	{
	SumStats::observe("end_of_conn", [$host=c$id$orig_h], [$num=c$orig$size]);
	}
