#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11820);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2003-0468", "CVE-2003-0540");
 script_bugtraq_id(8361, 8362);
 script_xref(name:"OSVDB", value:"6551");
 script_xref(name:"OSVDB", value:"10544");
 script_xref(name:"OSVDB", value:"10545");
 script_xref(name:"RHSA", value:"RHSA-2003:251-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:033");
 
 script_name(english: "Postfix < 2.0 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Postfix which is as old as or 
older than 1.1.12.

There are two vulnerabilties in this version which may allow an attacker
to remotely disable it, or to be used as a DDoS agent against arbitrary
hosts." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Postfix 2.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Checks the version of the remote Postfix daemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security");
 script_family(english: "SMTP problems");
 script_dependencie("smtpscan.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if ( report_paranoia < 2 )
 banner = get_kb_item("smtp/" + port + "/banner");
else
 banner = get_kb_item("smtp/" + port + "/real_banner");

if(!banner)exit(0);

if(ereg(pattern:".*Postfix 1\.(0\..*|1\.([0-9][^0-9]|1[0-2]))", string:banner)||
   ereg(pattern:".*Postfix 2001.*", string:banner))
{
 security_warning(port);
}
