#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11817);
  script_version("$Revision: 1.11 $");
  script_bugtraq_id(8385);
  script_xref(name:"OSVDB", value:"2396");

  script_name(english:"Stellar Docs Malformed Query Path Disclosure");
  script_summary(english:"SQL Injection and more.");
  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running StellarDocs

There is a flaw in this system which may allow an attacker to
obtain the physical path of the remote installation of StellarDocs.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to the latest version of this software'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/332565'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


function check(dir)
{
  local_var buf, req;
  req = http_get(item:dir + "/data/fetch.php?page='", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("mysql_num_rows()" >< buf)
  	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 return(0);
}

foreach dir (cgi_dirs())
{
 check(dir:dir);
}
