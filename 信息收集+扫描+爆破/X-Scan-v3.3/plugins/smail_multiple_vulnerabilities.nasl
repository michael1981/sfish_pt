#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17633);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2005-0892", "CVE-2005-0893");
 script_bugtraq_id(12899, 12922);
 script_xref(name:"OSVDB", value:"15065");
 script_xref(name:"OSVDB", value:"15066");
 
 script_name(english:"Smail-3 < 3.2.0.121 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running as its mail server
S-mail version 3.2.0.120 or older.  Such versions contain various
vulnerabilities that may allow an unauthenticated attacker execute
arbitrary code on the remote host by exploiting a heap overflow by
sending a malformed argument to the 'MAIL FROM' command." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0435.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0459.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0462.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0474.html " );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.weird.com/pub/local/smail-3.2.0.121.ChangeLog" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Smail 3.2.0.121 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks the version of the remote Smail daemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpscan.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include('smtp_func.inc');
port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if ( ! banner )exit(0);
if ( ereg(pattern:".* Smail(-)?3\.([01]\.|2\.0\.([0-9] |[0-9][0-9] |1[01][0-9] |120 ))", string:banner) ) security_hole(port);
