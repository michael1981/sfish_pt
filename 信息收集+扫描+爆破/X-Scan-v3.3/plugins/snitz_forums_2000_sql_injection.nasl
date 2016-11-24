#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (10/29/09)
# - Updated to use compat.inc (11/17/2009)


include("compat.inc");

if (description)
{
 script_id(14227);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0286");
 script_bugtraq_id(7549);
 script_xref(name:"OSVDB", value:"4638");

 script_name(english:"Snitz Forums 2000 < 3.4.03 register.asp Email Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The discussion forum running on the remote web server has a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Snitz Forum 2000.

This version allows an attacker to execute stored procedures 
and non-interactive operating system commands on the system. 

The problem stems from the fact that the 'Email' variable
in the register.asp module fails to properly validate and
strip out malicious SQL data.  

An attacker, exploiting this flaw, would need network access
to the webserver.  A successful attack would allow the 
remote attacker the ability to potentially execute arbitrary
system commands through common SQL stored procedures such 
as xp_cmdshell." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0067.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Snitz Forum 2000 version 3.4.03 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determine Snitz forums version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) 
	exit(0);

url = "/forum/register.asp";
buf = http_send_recv3(method:"GET", item:url, port:port);
if( isnull(buf) ) exit(0);

# Ex: Powered By: Snitz Forums 2000 Version 3.4.03

#if("Powered By: Snitz Forums 2000 3.3.03" >< buf[2] )
# jwl: per CVE, all version prior to 3.3.03 are vulnerable
if (egrep(string:buf[2], pattern:"Powered By: Snitz Forums 2000 ([0-2]\..*|3\.[0-2]\..*|3\.3\.0[0-2])"))
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    	exit(0);
}


