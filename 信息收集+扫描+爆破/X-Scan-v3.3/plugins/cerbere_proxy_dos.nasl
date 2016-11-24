#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14640);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(11085);
 script_xref(name:"OSVDB", value:"9454");
 script_xref(name:"Secunia", value:"12422");
 
 script_name(english:"Cerbere HTTP Proxy Server Host: Header Remote DoS");
 script_summary(english:"Checks for the version of the remote Cerbere Proxy");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote proxy server has a denial of service vulnerability."
 );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running Cerbere Proxy Server, a HTTP/FTP proxy\n",
      "server for Windows operating systems. It is reported that versions up\n",
      "to and including 1.2 are vulnerable to a remote denial of service in\n",
      "the 'Host:' HTTP field processing. An attacker may craft a malicious\n",
      "HTTP request with a large 'Host:' field to deny service to legitimate\n",
      "users."
    )
  );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/secunia/2004-q3/0442.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 3128);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3128);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ( egrep(pattern:"Cerb&egrave;re Proxy Server r.(0\.|1.[0-2][^0-9])", string:res) ) security_hole(port); 


