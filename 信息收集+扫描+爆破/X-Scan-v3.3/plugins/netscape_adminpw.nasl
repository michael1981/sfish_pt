#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10468);
  script_version ("$Revision: 1.23 $");

  script_bugtraq_id(1579);
  script_xref(name:"OSVDB", value:"367");

  script_name(english:"Netscape Administration Server /admin-serv/config/admpw Admin Password Disclosure");
  script_summary(english:"Attempts to read the Netscape configuration file admpw.");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The file /admin-serv/config/admpw is readable.

This file contains the encrypted password for the Netscape
administration server. Although it is encrypted, an attacker
may attempt to crack it by brute force."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove read access permissions for this file and/or stop
the Netscape administration server."
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/netscape-commerce", "www/netscape-fasttrack", "www/iplanet");
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Netscape" >!< sig && "SunONE" >!< sig ) exit(0);


res = is_cgi_installed_ka(item:"/admin-serv/config/admpw", port:port);
if(res)security_warning(port);
