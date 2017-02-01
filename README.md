Bro Phishing Detection Module
=============================

Phishing detection in Bro. 

Installation
-----------------------

```bash
cd <prefix>/share/bro/site/
git clone git://github.com/hosom/bro-phishing.git Phishing
echo "@load Phishing" >> local.bro
```

attachments.bro
-----------------------
A simple phishing detection for mass phishing campaigns like Dridex. Detects the same email attachment being sent to many recipients. 

**max_attachment_recipients** controls the threshold that this script will alert on. 

**exploit_types** are the file types to monitor. We can't monitor for just any filetype, otherwise certificates and signature files will result in an alert. 

**attachment_policy** is a hook that allows for complex tuning of this script. 

For example, if you wanted to ignore all email from the source *marketing@foo.com*, you would add the following to a script and load it after loading the **attachments.bro** script. 

```bro
hook Phishing::attachment_policy(f: fa_file) &priority=10
	{
	# Because this hook utilizes a file, rather than a connection object... the exception code can be 
	# longer than I would prefer.
	local ignore = F;
	
	for ( cid in f$conns) 
		{
		local c = f$conns[cid];
		if ( c?$smtp && c$smtp?$mailfrom && c$smtp$mailfrom == "<marketing@foo.com>" )
			{
			ignore = T;
			# This break controls the flow of the inner loop, not the hook.
			break;
			}
		}
		
	if (ignore)
		# This break controls the flow of the hook, based on the status posted to ignore
		break;
	}
```

levenshtein.bro
-----------------------
Detection of emails from domains close to domains within **Site::local_zones**.

**max_distance** is the maximum levenshtein distance that will cause an alert in the notice.log.

To monitor a domain, simply add it to the **Site::local_zones**.

Example hook for policy
-----------------------
```bro
hook policy(rec: SMTP::Info)
	{
	if ( Site::is_local_addr(rec$id$orig_h) )
		break; 
	}
```
