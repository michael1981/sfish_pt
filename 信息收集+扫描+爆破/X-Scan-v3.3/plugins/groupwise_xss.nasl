#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16174);
  script_version("$Revision: 1.8 $");
  script_bugtraq_id(12310);
  script_xref(name:"OSVDB", value:"13134");
  script_xref(name:"OSVDB", value:"13135");
  
  script_name(english:"Novell GroupWise 6.5.3 WebAccess Multiple XSS");
  script_summary(english:"Checks GroupWare XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, a commercial
groupware package.

The remote version of this software is affected by multiple cross-site
scripting flaws due to a lack of sanitization of user-supplied data.

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0606.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}


include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

r = http_send_recv3(method:"GET",item:"/servlet/webacc?User.lang=<script>foo</script>", port:port);
if( r == NULL )exit(0);

if("/com/novell/webaccess/images/btnlogin<script>foo</script>.gif" >< r[2] )
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
