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
 script_id(11087);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-0714");
 script_bugtraq_id(3378);
 script_xref(name:"OSVDB", value:"9302");
 
 script_name(english: "Sendmail < 8.12.1 RestrictQueueRun Option Multiple Argument Local DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number,
might be vulnerable to a queue destruction when a local user
runs
	sendmail -q -h1000

If you system does not allow users to process the queue (which
is the default), you are not vulnerable.

Note that this vulnerability is _local_ only." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail 8.12.1 or later. As a workaround, do not allow users to 
process the queue (RestrictQRun option)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P" );
script_end_attributes();

 script_summary(english: "Checks the version number for 'queue destruction'");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc."); 
 script_family(english: "SMTP problems");
 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
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
