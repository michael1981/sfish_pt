#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11769);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(7999, 8000, 8001);
 script_xref(name:"OSVDB", value:"58281");
 script_xref(name:"OSVDB", value:"58284");
 
 script_name(english:"Zope Invalid Query Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is prone to
an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote Zope web server may be forced into disclosing its physical
path when it receives bad arguments for several example CGIs included
in the installation." );
 script_set_attribute(attribute:"see_also", value:"http://exploitlabs.com/files/advisories/EXPL-A-2003-009-zope.txt" );
 script_set_attribute(attribute:"solution", value:
"Delete the directory '/Examples'." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for Zope Examples directory");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/zope");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);	# We should also try 8080

u = "/Examples/ShoppingCart/addItems?orders.id%3Arecords=510-007&orders.quantity%3Arecords=&orders.id%3Arecords=510-122&orders.quantity%3Arecords=0&orders.id%3Arecords=510-115&orders.quantity%3Arecords=0";

r = http_send_recv3(method: "GET", port:port, item: u);
if (isnull(r)) exit(0);
a = r[2];

if("invalid literal for int()" >< a && "Publish.py"  >< a)
{
  security_warning(port);
  }
