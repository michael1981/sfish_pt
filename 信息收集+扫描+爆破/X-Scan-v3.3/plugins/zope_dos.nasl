#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10702);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2001-0568");
 script_bugtraq_id(2458);
 script_xref(name:"OSVDB", value:"6285");
 
 script_name(english:"Zope ZClass Modification Local DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application server that is prone to
a denial of service issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server is Zope < 2.2.5.  Such versions allow any Zope
user to create a denial of service by modifying Zope data structures,
thus rendering the site unusable. 

*** Since Nessus solely relied on the version number of your server, 
*** consider this a false positive if you applied the hotfix already." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zope 2.2.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for Zope");
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
  if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\.[0-4]))", 
  		string:banner))
     security_warning(port);
}

