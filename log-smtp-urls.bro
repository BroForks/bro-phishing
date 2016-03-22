##! Create a log containing all links seen in emails

module Phishing;

@load base/protocols/smtp
@load base/utils/urls

export {
	## Create log stream
	redef enum Log::ID += { Links_LOG };

	type Info: record {
		## Timestamp pulled from the SMTP record
		ts:		time &log;
		## Connection UID to tie the log to the conn log
		uid:	string &log;
		## SMTP MAILFROM header
		from:	string &log;
		## SMTP RCPTTO header
		to: 	set[string] &log;
		## The host portion of the URL found
		host: 	string &log;
		## The path of the URL found
		path:	string	&log;
	};

	## Event fired when a link is found in an email
	global link_found: event(uri: URI);
}

event bro_init()
	{
	Log::create_stream(Phishing::Links_LOG, [$columns=Info]);
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	if ( ! c?$smtp )
		return;

	# Get all of the URLs from the mime data
	local urls = find_all_urls_without_scheme(data);
	# Loop through each of the links, logging them
	for ( url in urls )
		{
		local uri = decompose_uri(url);
		event Phishing::link_found(uri);

		local i: Info;

		i$ts = c$smtp$ts;
		i$uid = c$smtp$uid;
		i$from = c$smtp$mailfrom;
		i$to = c$smtp$rcptto;
		i$host = uri$netlocation;
		i$path = uri$path;

		Log::write(Links_LOG, i);
		}
	}