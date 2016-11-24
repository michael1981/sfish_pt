#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10364);
  script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2000-1196");
  script_xref(name:"OSVDB", value:"278");

  script_name(english:"Netscape PSCOErrPage.htm errPagePath Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks if /PSUser/PSCOErrPage.htm reads any file");
  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The '/PSUser/PSCOErrPage.htm' CGI allows a  malicious user to view
any file on the target computer by issuing a GET request :

  GET  /PSUser/PSCOErrPage.htm?errPagePath=/file/to/read"
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Netscape PublishingXpert 2.5 SP2 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://packetstormsecurity.org/0004-exploits/ooo1.txt'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  req = http_get(item:"/PSUser/PSCOErrPage.htm?errPagePath=/etc/passwd", port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if ( result == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}
