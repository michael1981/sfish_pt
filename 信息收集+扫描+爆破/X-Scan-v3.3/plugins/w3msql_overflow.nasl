#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10296);
  script_version ("$Revision: 1.30 $");
  script_cve_id("CVE-2000-0012");
  script_bugtraq_id(898);
  script_xref(name:"OSVDB", value:"232");

  script_name(english:"Mini SQL CGI content-length Field Remote Overflow");
  script_summary(english:"Overflow in w3-msql");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The mini-sql program comes with the w3-msql CGI which is vulnerable
to a buffer overflow.

An attacker may use it to gain a shell on this system."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Contact the vendor for a patch or remove the CGI.
A patch was also provided with the original disclosure notice."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/1999-q4/0475.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

flag = 0;
cgi = "w3-msql/index.html";

foreach dir (cgi_dirs())
{
 if (is_cgi_installed3(port:port, item:string(dir, "/", cgi)))
 {
  flag = 1;
  directory = dir;
  break;
 }
}

if(!flag)exit(0);


r = http_send_recv3(method:"POST", item: directory + "/w3-msql/index.html",
  port: port, content_type: "multipart/form-data", data: crap(16000));

if (http_is_dead(port: port))
       security_hole(port);
