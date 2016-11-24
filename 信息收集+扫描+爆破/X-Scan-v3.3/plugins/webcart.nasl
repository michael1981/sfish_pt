#
# (C) Tenable Network Security, Inc.
#

#
# Written after the advisory of MindSec
#

include( 'compat.inc' );

if(description)
{
  script_id(10298);
  script_version ("$Revision: 1.26 $");
  script_cve_id("CVE-1999-0610");
  script_bugtraq_id(2281);

  script_name(english:"Webcart Default Install Configuration Disclosure");
  script_summary(english:"Checks for the webcart misconfiguration.");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"At least one of these file or directories is world readable :

  /webcart/orders/
  /webcart/orders/import.txt
  /webcart/carts/
  /webcart/config/
  /webcart/config/clients.txt
  /webcart-lite/orders/import.txt
  /webcart-lite/config/clients.txt

This misconfiguration may allow an attacker to gather the credit card numbers
of your clients."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Restrict read permissions on the webcart directories."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=92462991805485&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

c[0] = "/webcart/orders/";
c[1] = "/webcart/orders/carts/.txt";
c[2] = "/webcart/config/";
c[3] = "/webcart/carts/";
c[4] = "/webcart/config/clients.txt";
c[5] = "/webcart-lite/config/clients.txt";
c[6] = "/webcart-lite/orders/import.txt";
c[7] = "";

for(i = 0 ; c[i] ; i = i + 1)
{
  if(is_cgi_installed3(item:c[i], port:port))
  {
    security_warning(port);
    exit(0);
  }
}
