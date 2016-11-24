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
 script_id(11086);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-0713");
 script_bugtraq_id(3377);
 script_xref(name:"OSVDB", value:"9301");
 
 script_name(english: "Sendmail -C Malformed Configuration Privilege Escalation");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a privilege escalation attack." );
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be 
vulnerable to a 'Mail System Compromise' when a user supplies a custom
configuration file.
Although the mail server is suppose to run as a non-privileged user, 
a programming error allows the local attacker to regain the extra 
dropped privileges and run commands as root." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Sendmail." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();
		    
 script_summary(english: "Checks sendmail version number for 'custom config file'");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc."); 
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:".*Sendmail.*[^/]8\.12\.0.*", string:banner))
 	security_warning(port);
