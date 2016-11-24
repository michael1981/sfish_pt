#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16183);
  script_version("$Revision: 1.8 $");
  script_cve_id("CVE-2005-0296");
  script_bugtraq_id(12285);
  script_xref(name:"OSVDB", value:"13141");
  script_xref(name:"OSVDB", value:"13142");
 
  script_name(english:"Novell GroupWise WebAccess Error Handler Authentication Bypass");
  script_summary(english:"Checks GroupWise Auth Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, a commercial
groupware package.

The remote version of this software is prone to an authentication
bypass attack. 

An attacker requesting :

	/servlet/webacc?error=webacc

may bypass the authentication mechanism and gain access to the groupware
console." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/387566/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

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

r = http_send_recv3(method:"GET", item:"/servlet/webacc?error=webacc", port:port);
if( r == NULL )exit(0);

if ( "<TITLE>Novell WebAccess ()</TITLE>" >< r[2] &&
     "/servlet/webacc?User.context=" >< r[2] )
	security_warning(port);
