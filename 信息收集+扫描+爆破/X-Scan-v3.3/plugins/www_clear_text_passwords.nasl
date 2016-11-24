#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(26194);
 script_version ("$Revision: 1.7 $");

 script_name(english: "Web Server Uses Plain Text Authentication Forms");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server might transmit credentials in cleartext." );
 script_set_attribute(attribute:"description", value:
"The remote web server contains several HTML form fields containing
an input of type 'password' which transmit their information to
a remote web server in cleartext.

An attacker eavesdropping the traffic between web browser and 
server may obtain logins and passwords of valid users." );
 script_set_attribute(attribute:"solution", value:
"Make sure that every sensitive form transmits content over HTTPS." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 script_summary(english: "Uses the results of webmirror.nasl");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

kb = get_kb_item("www/" + port + "/ClearTextPasswordForms");
if ( kb )
  security_warning(port:port, extra: kb);
