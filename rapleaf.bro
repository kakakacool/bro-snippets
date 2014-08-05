##! API wrapper for the RapLeaf personalization API.
# API docs can be found here: 
# http://www.rapleaf.com/developers/personalization-api/personalization-api-documentation/#optional_params

module Rapleaf;

export {
	type Gender: enum {
		MALE,
		FEMALE
	};

	type Result: record {
		gender: Gender &optional;
		age: string &optional;
	};

	## Your Rapleaf.com api key must be defined in order for API
	## to work.
	const api_key = "" &redef;

	## Do a RapLeaf lookup based upon an email address. This is an
	## async function that must be called within a when statement.  
	## 
	## email: The email address to lookup.
	##
	## Returns: The data retrieved from Rapleaf.
	const lookup: function(email: string): Rapleaf::Result &redef;
}

function get_val(key_val: string): string
	{
	return find_last(key_val, /\"[^\"]*\"/)[1:-2];
	}

function get(json_string: string, key: string): string
	{
	local mkey = cat("\"", key, "\"");
	if ( mkey in json_string )
		{
		local parts = split_n(json_string, /,\"/, F, 100);
		for ( i in parts )
			{
			if ( key in parts[i] )
				{
				return get_val(parts[i]);
				#return gsub(parts[i], /(^.*\":\")|(\"?[^\"]*$)/, "");
				}
			}
		}
	else
		return "";
	}

function lookup(email: string): Rapleaf::Result
	{
	local result = Result();

	if ( api_key == "" )
		{
		Reporter::warning("No Rapleaf API key is defined!");
		return result;
		}

	local sha1_email = sha1_hash(to_lower(email));
	local url = fmt("https://personalize.rapleaf.com/v4/dr?sha1_email=%s&api_key=%s&show_available=true", sha1_email, api_key);
	return when ( local r = ActiveHTTP::request([$url=url]) )
		{
		if ( r$code == 200 )
			{
			local g = get(r$body, "gender");
			if ( g == "Male" )
				result$gender = MALE;
			else if ( g == "Female" )
				result$gender = FEMALE;

			result$age = get(r$body, "age");
			}
		return result;
		}
	}