#
# (C) Tenable Network Security, Inc.

include( 'compat.inc' );

if (description)
{
 script_id(11753);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(7952);
 script_xref(name:"OSVDB", value:"53325");
 script_xref(name:"OSVDB", value:"53326");

 script_name(english:"SquirrelMail Multiple Remote Vulnerabilities");
 script_summary(english:"Determine if squirrelmail reads arbitrary files");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running SquirrelMail, a web-based mail server.

There is a flaw in the remote installation which may allow an
attacker with a valid webmail account to read, move and delete arbitrary
files on this server, with the privileges of the HTTP server.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to SquirrelMail 1.2.12 when it is available.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2003-06/0176.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


dir = make_list( cgi_dirs(), "/mail");


foreach d (dir)
{
 req = http_get(item:d + "/src/redirect.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if(egrep(pattern:"SquirrelMail version (0\..*|1\.([0-1]\..*|2\.([0-9]|1[01])))[^0-9]", string:res))
 {
  security_hole(port);
  exit(0);
 }
}
