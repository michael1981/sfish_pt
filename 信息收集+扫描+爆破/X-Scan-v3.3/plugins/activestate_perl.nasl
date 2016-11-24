#
# (C) Tenable Network Security, Inc.
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#

include("compat.inc");

if(description)
{
   script_id(11007);
   script_version ("$Revision: 1.15 $");
   script_xref(name:"OSVDB", value:"826");
   script_name(english:"ActivePerl findtar Sample Script Remote Command Execution");
   script_summary(english:"Determines if ActivePerl is vulnerable");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a scripting language that is affected by a
remote command execution flaw.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ActiveState Perl which is
affected by a remote command execution flaw. An attacker could exploit
this flaw in order to execute arbitrary commands in the context of the
affected application.");
 
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/win2ksecadvice/2000-q4/0114.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrading to version 5.6.3 or newer reportedly fixes the
vulnerability." );
 script_set_attribute(attribute:"cvss_vector", value: 
 "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
   script_category(ACT_ATTACK);
 
   script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
   script_family(english:"CGI abuses");
   script_dependencie("find_service1.nasl", "http_version.nasl");
   script_require_ports("Services/www", 80);
   exit(0);
}


#
# The code starts here
# 
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

w = http_send_recv3(method:"GET", port:port, item:'/."./."./winnt/win.ini%20.pl');
r = strcat(r[0], r[1], '\r\n', r[2]);
if("Semicolon seems to be missing at" >< r)
{
 security_hole(port);
}
