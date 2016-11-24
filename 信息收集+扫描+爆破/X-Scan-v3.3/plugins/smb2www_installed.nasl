#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11377);
  script_version("$Revision: 1.7 $");

  script_name(english:"smb2www Proxy Bypass");
  script_summary(english:"smb2www Detection");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote CGI is vulnerable to an access control breach."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running smb2www - a SMB to WWW gateway.

An attacker may use this CGI to use this host as a proxy -
he can connect to third parties SMB host without revealing
his IP address."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Enforce proper access controls to this CGI"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = make_list("/samba");

foreach d (cgi_dirs())
{
 dirs = make_list(dirs, d, string(d, "/samba"));
}

foreach d (dirs)
{
 req = http_get(item:string(d, "/smb2www.pl"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if("Welcome to the SMB to WWW gateway" >< res){
 	security_warning(port);
	exit(0);
	}
}
