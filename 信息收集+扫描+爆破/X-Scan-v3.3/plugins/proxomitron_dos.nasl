#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11752);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(7954);
 script_xref(name:"OSVDB", value:"55311");

 script_name(english:"Proxomitron GET Request Overflow Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Proxomitron proxy. There might be a bug
in this software which may allow an attacker to disable it remotely.

*** Nessus did not check for the presence of the flaw, so this might
*** be a false positive." );
 script_set_attribute(attribute:"solution", value:
"Upgrade this software if needed or replace it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Checks for the presence of proxomitron");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "proxy_use.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);
res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if( "<title>The Proxomitron Reveals...</title>" >< res ) security_warning(port);
