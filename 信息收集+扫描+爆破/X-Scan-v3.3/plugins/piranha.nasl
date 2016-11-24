#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10381);
 script_bugtraq_id(1148);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0248");
 script_xref(name:"OSVDB", value:"289");
 script_name(english:"Piranha's RH6.2 default password");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application accepts well known passwords." );
 script_set_attribute(attribute:"description", value:
"The 'piranha' package is installed on the remote host.
This package, as it is distributed with Linux RedHat 6.2, comes with the
login/password combination 'piranha/q' or 'piranha'/'piranha'.

An attacker may use it to reconfigure your Linux Virtual Servers (LVS)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade piranha-gui, piranha and piranha-docs to version 0.4.13" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "logs into the remote piranha subsystem");
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
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
if (!can_host_php(port:port)) exit(0);

function test_hole(port, user, pass)
{
 local_var r, res, u;

 u = "/piranha/secure/control.php3?";
 r = http_send_recv3(method: "GET", item: u, port:port, username: user, password: pass);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if("Piranha (Control/Monitoring)" >< res)
    {
      security_hole(port, extra: strcat('\nIt was possible to log to :\n\n', 
build_url(port: port, qs: u), '\nwith username=', user, ' and password=', pass, '\n'));
      exit(0);
    }
}

test_hole(port:port, user: "piranha", pass: "q");
test_hole(port:port, user: "piranha", pass: "piranha");   

