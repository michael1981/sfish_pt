#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_version ("$Revision: 1.11 $");
 script_id(11522);

 script_xref(name:"OSVDB", value:"821");

 script_name(english: "Linksys Router Default Password (admin)");
 
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log on the remote device with a default password." );
 script_set_attribute(attribute:"description", value:
"The remote Linksys device has its default password ('admin') set. 
An attacker may connect to it and reconfigure it using this account." );
 script_set_attribute(attribute:"solution", value:
"Connect to this port with a web browser, and click on the 'Password'
section to set a strong password." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Tests for the linksys default account");
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CISCO");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

n = 0;
login[n] = "";		pass[n++] = "admin";
login[n] = "admin";	pass[n++] = "admin";

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

res = http_get_cache(item:"/", port:port);
if (isnull(res)) exit(0);
if (! egrep(pattern: "^HTTP/[01.]+ +401 ", string: res)) exit(0);

for (i = 0; i < n; i ++)
{
  r = http_send_recv3(port: port, method: 'GET', item: '/',
        username: login[i], password: pass[i]);
  if (isnull(r)) exit(0);
  if (r[0] =~  "^HTTP/[01.]+ 200 ")
  {
    security_hole(port, extra: strcat(
'\nIt was possible to log with the following credentials :',
'\nusername : ', login[i],
'\npassword : ', pass[i], '\n'));
    break;
  }
}
