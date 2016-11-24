#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11661);
 script_version("$Revision: 1.8 $");
 
 script_name(english:"iisPROTECT Unpassworded Administrative Interface");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application with no password." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iisprotect, an IIS add-on to protect the
pages served by this server.

However, the administration module of this interface has not been
password protected. As a result, an attacker may perform 
administrative tasks without any authentication." );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for accessing this page." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 script_summary(english:"Determines if iisprotect is password-protected");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

res = http_send_recv3(method:"GET",item:"/iisprotect/admin/GlobalAdmin.asp?V_FirstTab=GlobalSetting", port:port);
if (isnull(res)) exit(1, "The remote web server did not respond.");

if ("<form action='/iisprotect/admin/GlobalAdmin.asp' method='POST'" >< res[2]) security_hole(port:port);
