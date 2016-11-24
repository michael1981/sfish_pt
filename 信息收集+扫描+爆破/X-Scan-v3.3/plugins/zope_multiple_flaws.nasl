#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11985);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(9400);
 script_xref(name:"OSVDB", value:"3449");
 script_xref(name:"OSVDB", value:"10312");
 script_xref(name:"OSVDB", value:"10313");
 script_xref(name:"OSVDB", value:"10314");
 script_xref(name:"OSVDB", value:"10315");
 script_xref(name:"OSVDB", value:"10316");
 script_xref(name:"OSVDB", value:"10317");
 script_xref(name:"OSVDB", value:"10318");
 script_xref(name:"OSVDB", value:"10319");
 script_xref(name:"OSVDB", value:"10320");
 script_xref(name:"OSVDB", value:"10321");
 script_xref(name:"OSVDB", value:"10322");
 script_xref(name:"OSVDB", value:"10323");
 script_xref(name:"OSVDB", value:"10324");
 script_xref(name:"OSVDB", value:"10325");
 script_xref(name:"OSVDB", value:"10326");
 
 script_name(english:"Zope < 2.6.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web server is a version of Zope which is older than version
2.6.3. 

There are multiple security issues in all releases prior to version
2.6.3 or 2.7 BETA4 which can be exploited by an attacker to perform
cross-site scripting attacks, obtain information about the remote
host, or disable this service remotely. 

Note that Nessus solely relied on the version number of your server,
so if the hotfix has already been applied, this might be a false
positive" );
 script_set_attribute(attribute:"see_also", value:"http://mail.zope.org/pipermail/zope-announce/2004-January/001325.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.6.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks Zope version"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: .*Zope 2\.(([0-5]\..*)|(6\.[0-2][^0-9])|(7\..*BETA *[0-3]))", 
  		string:banner))
  {
     security_warning(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
