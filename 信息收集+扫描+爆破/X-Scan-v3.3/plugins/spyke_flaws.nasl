#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Marc Bromm" <theblacksheep@fastmail.fm>
#  To: bugtraq@securityfocus.com
#  Date: Mon, 09 Jun 2003 09:25:19 -0800
#  Subject: Several bugs found in "Spyke's PHP Board"

include( 'compat.inc' );

if(description)
{
 script_id(11706);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(7856);
 script_xref(name:"OSVDB", value:"4388");
 script_xref(name:"OSVDB", value:"4389");

 script_name(english:"Spyke Multiple Remote Vulnerabilities");
 script_summary(english:"Checks for the presence of info.dat");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to a information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is using Spyke - a web board written in PHP.

This board stores vital information in the file info.dat,
which may be downloaded by anyone. This file contains
the name of the administrator of the web site, as well as
its password.

Another flaw lets an attacker download any information about
any user simply by knowing their name.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'There are no known fix.  Discontinue use of Spyke.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2003-06/0098.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl","http_version.nasl");
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



function check(loc)
{
 local_var r, req;

 req = http_get(item:string(loc, "/info.dat"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("$adminpw" >< r )
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}
