#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11622);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2002-1157");
 script_bugtraq_id(6029);
 script_xref(name:"OSVDB", value:"2107");
 
 script_name(english:"Apache mod_ssl Host: Header XSS");
 script_summary(english:"Checks for version of mod_ssl");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server module has a cross-site scripting vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to the web server banner, the version of mod_ssl running\n",
     "on the remote host has a cross-site scripting vulnerability.  A\n",
     "remote attacker could exploit this by tricking a user into\n",
     "requesting a maliciously crafted URL, resulting in stolen\n",
     "credentials.\n\n",
     "*** Note that several Linux distributions (such as RedHat)\n",
     "*** patched the old version of this module. Therefore, this\n",
     "*** might be a false positive. Please check with your vendor\n",
     "*** to determine if you really are vulnerable to this flaw."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-10/0374.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_ssl 2.8.10 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner || backported)exit(0);
 
serv = strstr(banner, "Server");
if("Apache/" >!< serv ) exit(0);
if("Apache/2" >< serv) exit(0);
if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-9][^0-9])).*", string:serv))
{
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
