#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(18114);
  script_version("$Revision: 1.4 $");
  script_cve_id("CVE-2005-1232");
  script_bugtraq_id(13268);
  script_xref(name:"OSVDB", value:"15699");

  script_name(english:"Sun Java System Web Proxy Server Unspecified Remote Overflow");
  script_summary(english:"Checks for version of SunOne Web Proxy");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running the SunOne Web Proxy. This version is reported
vulnerable to a number of remote buffer overflow.  Alledgedly, successful
exploitation would result in the attacker executing arbitrary commands on
the remote SunOne Web Proxy server.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to 3.6 SP7 or higher'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://sunsolve.sun.com/search/document.do?assetkey=1-%3Cbr/%3E%20%20%20%20%20%20%20%20%20%20%20%20%20%20%2026-57763-1'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, 443);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if(ereg(pattern:"^Forwarded: .* \(Sun-ONE-Web-Proxy-Server/([0-2]\..*|3\.([0-5]\..*|6(\)|-SP[0-6])))", string:banner))
 {
   security_hole(port);
 }
