Bro Phishing Detection Module
=============================

This module was created for the purpose of detecting phishing emails. 

Example hook for policy
-----------------------

hook policy(rec: SMTP::Info)
	{
	if ( Site::is_local_addr(rec$id$orig_h) )
		break; 
	}