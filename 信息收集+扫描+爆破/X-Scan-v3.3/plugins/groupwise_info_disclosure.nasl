#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16175);
  script_version("$Revision: 1.8 $");
  script_bugtraq_id(12194);
  script_xref(name:"OSVDB", value:"13021");
  
  script_name(english:"Novell GroupWise WebAccess WebAccessUninstall.ini Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, a commercial
groupware package.

The remote version of this software has an information disclosure
vulnerability.  An attacker may request the file
'/com/novell/webaccess/WebAccessUninstall.ini' and will obtain some
information about the remote host paths and setup." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0228.html" );
 script_set_attribute(attribute:"solution", value:
"Delete /com/novell/webaccess/WebAccessUninstall.ini" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

 script_end_attributes();

  script_summary(english:"Checks GroupWare WebAccessUninstall.ini");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);


r = http_send_recv3(method:"GET", item:"/com/novell/webaccess/WebAccessUninstall.ini", port:port);
if( r == NULL )exit(0);

if("NovellRoot=" >< r[2] )
{
  security_warning(port);
#  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
