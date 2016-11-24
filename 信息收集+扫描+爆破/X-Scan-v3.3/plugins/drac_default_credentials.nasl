#
# (C) Tenable Network Security, Inc.
#

# Thanks to Jason Haar for his help!


include("compat.inc");

if(description)
{
 script_id(35029);
 script_version ("$Revision: 1.11 $");
 
 script_name(english: "Dell Remote Access Controller Default Password (calvin) for 'root' Account");
     
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is protected using a known set of credentials." );
 script_set_attribute(attribute:"description", value:
"It is possible to gain access to the Dell Remote Access Controller
(DRAC) using a known set of credentials.  A remote attacker can
leverage this issue to take full control of the hardware." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/DRAC#Access" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73b6b892" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb0507dc" );
 script_set_attribute(attribute:"solution", value:
"Change the password or disable this account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Tries to log into remote DRAC");
 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 443, embedded: TRUE);

page = http_send_recv3(port: port, method:'GET', item: "/", follow_redirect:1);
if ( isnull(page) ) exit(0);
if ("<title>Remote Access Controller</title>" >!< page[2]) exit(0);

enable_cookiejar();

i = 0;
drac_field[i] = "hash";
drac_url[i] = "/cgi/login";
drac_ver[i++] = "DRAC4";

drac_field[i] = "password";
drac_url[i] = "/cgi-bin/webcgi/login";
drac_ver[i++] = "DRAC5";

function test_drac(port, username, password)
{
 local_var	r, extra, f;

 for (i = 0; drac_field[i]; i ++)
 {
   clear_cookiejar(); 
   r = http_send_recv3(port: port, method: 'POST', item: drac_url[i],
    data: strcat("user=", username, "&", drac_field[i], "=", password),
    follow_redirect: 0, 
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
   if (isnull(r)) continue;  # Drac4 returns nothing?
   if (r[0] !~ "^HTTP/1\.[01] +404 ")
   {
    if (egrep(pattern: "^Set-Cookie2?:", string: r[1], icase: 1))
    {
      extra = strcat('\nIt was possible to log into the remote ', drac_ver[i], ' at the\n',
                 'following URL :\n\n  ', 
                 build_url(port: port, qs:drac_url[i]), 
                 '\n\nwith the following credentials :\n\n  - Username : ', username, '\n  - Password : ', password, '\n');
     security_hole(port: port, extra: extra);
     exit(0);
    }
   }
 }
}

test_drac(port: port, username: "root", password: "calvin");
