#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(16200);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2004-1315");
 script_bugtraq_id(10701);
 script_xref(name:"OSVDB", value:"11719");
 script_xref(name:"OSVDB", value:"11961");
 script_xref(name:"OSVDB", value:"11962");

 script_name(english:"phpBB < 2.0.11 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB older than 2.0.11.

It is reported that this version of phpBB is susceptible to a script
injection vulnerability which may allow an attacker to execute arbitrary
code on the remote host.

In addition, phpBB has been reported to multiple SQL injections, 
although Nessus has not checked for them." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB 2.0.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for the version of phpBB");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

version = matches[1];
if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[01])[^0-9])", string:version))
	security_hole(port);

