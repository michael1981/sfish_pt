#
# (C) Tenable Network Security, Inc.
#

# http://collector.zope.org/Zope/359
#


include("compat.inc");

if(description)
{
 script_id(11234);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(5806);
 script_xref(name:"OSVDB", value:"58285");
 
 script_name(english: "Zope Malformed XML RPC Request Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is prone to
an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"There is a minor security problem in all releases of Zope prior to
version 2.5.1b1 - they reveal the installation path when an invalid
XML RPC request is sent." );
 script_set_attribute(attribute:"see_also", value:"https://bugs.launchpad.net/zope2/+bug/142016" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.5.1b1 / 2.6.0b1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english: "Checks for Zope installation directory");
 script_category(ACT_ATTACK);
 script_copyright(english: "This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# The proof of concept request was:
# POST /Documentation/comp_tut HTTP/1.0
# Host: localhost
# Content-Type: text/xml
# Content-length: 93
# 
# <?xml version="1.0"?>
# <methodCall>
# <methodName>objectIds</methodName>
# <params/>
# </methodCall>
#
# but it does not seem to be necessary IIRC.

# uri = "/Foo/Bar/Nessus"
uri = strcat( "/", rand_str(charset: "bcdfghjklmnpqrstvwxz", length: 5),
      	       "/", rand_str(charset: "bcdfghjklmnpqrstvwxz", length: 6),
	        "/", rand_str(charset: "bcdfghjklmnpqrstvwxz", length: 7) );
r = http_send_recv3(port: port, method: 'POST', item: uri);
if (egrep(string: r[2], 
         pattern: "(File|Bobo-Exception-File:) +(/[^/]*)*/[^/]+.py"))
  security_warning(port);
