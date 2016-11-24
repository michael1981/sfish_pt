#
# (C) Tenable Network Security, Inc.
#

# References:
# From: "Michal Zalewski" <lcamtuf@echelon.pl>
# To: bugtraq@securityfocus.com
# CC: sendmail-security@sendmail.org
# Subject: RAZOR advisory: multiple Sendmail vulnerabilities


include("compat.inc");

if(description)
{
 script_id(11088);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2001-0715");
 script_bugtraq_id(3898);
 script_xref(name:"OSVDB", value:"9303");
 
 script_name(english: "Sendmail RestrictQueueRun Option Debug Mode Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"According to the version number of the remote mail server, 
a local user may be able to obtain the complete mail configuration
and other interesting information about the mail queue even if
he is not allowed to access those information directly, by running
	sendmail -q -d0-nnnn.xxx
where nnnn & xxx are debugging levels.

If users are not allowed to process the queue (which is the default)
then you are not vulnerable.

This vulnerability is _local_ only." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Sendmail or 
do not allow users to process the queue (RestrictQRun option)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english: "Check sendmail version number for 'debug mode leak'");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");
 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:"Sendmail.*[^/]8\.(([0-9]\..*)|(1[01]\..*)|(12\.0)).*",
	string:banner))
	security_note(port);
