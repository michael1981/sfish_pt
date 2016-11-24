#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10389);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2000-0429");
 script_bugtraq_id(1153);
 script_xref(name:"OSVDB", value:"294");
 
 script_name(english:"Cart32 Backdoor Password Arbitrary Command Execution");
 script_summary(english:"Determines the presence of Cart32");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A web application running on the remote host has a backdoor."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The Cart32 e-commerce shopping cart is installed. This software\n",
     "contains multiple security flaws.\n\n",
     "There is a backdoor password of 'wemilo' in cart32.exe. This backdoor\n",
     "allows a remote attacker to run arbitrary commands in the context of\n",
     "the web server, and access credit card information.\n\n",
     "Additionally, it may be possible to change the administrator password\n",
     "by going directly to :\n\n",
     "/c32web.exe/ChangeAdminPassword"
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0069.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Cart32 version 5.0 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

foreach dir (cgi_dirs())
{
 url = string(dir, "/cart32.exe");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if ( isnull(res) ) exit(0);
 if ( egrep(pattern:"<title>Cart32 [0-2]\.", string:res) )
	{
	security_hole(port);
	exit(0);
	}
}
	
