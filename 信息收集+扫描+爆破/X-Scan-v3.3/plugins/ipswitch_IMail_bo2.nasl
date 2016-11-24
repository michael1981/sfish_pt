#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(15771);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2004-1520");
 script_bugtraq_id(11675);
 script_xref(name:"OSVDB", value:"11838");
 
 script_name(english:"Ipswitch IMail IMAP Service DELETE Command Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Ipswitch IMail which
is older than version 8.14.0.

The remote version of this software is vulnerable to a buffer overflow
when it processes the argument of the 'delete' command. An attacker
may exploit this flaw to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0182.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMail 8.14 or later, as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for version of IMail web interface");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
if ( ! banner ) exit(0);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/([1-7]\..*|(8\.(0[0-9]?[^0-9]|1[0-3][^0-9])))", string:serv))
   security_warning(port);

