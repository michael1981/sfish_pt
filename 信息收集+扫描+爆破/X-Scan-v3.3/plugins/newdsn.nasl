#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10360);
  script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-1999-0191");
  script_bugtraq_id(1818);
  script_xref(name:"OSVDB", value:"275");

  script_name(english:"Microsoft IIS newdsn.exe Arbitrary File Creation");
  script_summary(english:"Checks for the presence of /scripts/tools/newdsn.exe");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The CGI /scripts/tools/newdsn.exe is present.

This CGI allows any attacker to create files anywhere on your system if your
NTFS permissions are not tight enough, and can be used to overwrite DSNs of
existing databases."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove newdsn.exe"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/1997_3/0456.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
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

cgi = "/scripts/tools/newdsn.exe";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
