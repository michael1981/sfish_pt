#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(34850);
 script_version ("$Revision: 1.4 $");

 script_name(english: "Web Server Uses Basic Authentication");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server seems to transmit credentials in clear text." );
 script_set_attribute(attribute:"description", value:
"The remote web server contains web pages that are protected by 'Basic'
authentication over plain text. 

An attacker eavesdropping the traffic might obtain logins and passwords
of valid users." );
 script_set_attribute(attribute:"solution", value:
"Make sure that HTTP authentication is transmitted over HTTPS." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();


 script_summary(english: "Uses the results of webmirror.nasl");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_port_transport(port) > ENCAPS_IP) exit(0);

report = '';
for (i = 0; i < 64; i ++)
{
  url = get_kb_item(strcat("www/", port, "/content/basic_auth/url/", i));
  realm = get_kb_item(strcat("www/", port, "/content/basic_auth/realm/", i));
  len = strlen(url);
  if (strlen(realm) == 0 || len == 0) break;
  if (len > 31) len = 1;
  else len = 32 - len;
  report += strcat(url, ':/ ', realm, '\n');
}

if (strlen(report) > 0)
 security_note(port:port, extra:'\nThe following pages are protected.\n'+report);
