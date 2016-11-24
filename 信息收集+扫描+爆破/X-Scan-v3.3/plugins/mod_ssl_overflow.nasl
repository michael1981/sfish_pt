#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>,
# with the impulsion of H D Moore on the Nessus Plugins-Writers list

include("compat.inc");

if(description)
{
 script_id(10888);
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0082");
 script_bugtraq_id(4189);
 script_xref(name:"OSVDB", value:"756");
 
 script_name(english:"Apache mod_ssl i2d_SSL_SESSION Function SSL Client Certificate Overflow");
 script_summary(english:"Checks for version of mod_ssl");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server module has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to the web server banner, the remote host is using a\n",
     "vulnerable version of mod_ssl.  This version has a buffer overflow\n",
     "vulnerability.  A remote attacker could exploit this issue to execute\n",
     "arbitrary code.\n\n",
     "*** Some vendors patched older versions of mod_ssl, so this\n",
     "*** might be a false positive. Check with your vendor to determine\n",
     "*** if you have a version of mod_ssl that is patched for this\n",
     "*** vulnerability."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-02/0313.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_ssl 2.8.7 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
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

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner || backported)exit(0);

serv = strstr(banner, "Server");
if("Apache/" >!< serv ) exit(0);
if("Apache/2" >< serv) exit(0);
if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-6][^0-9])).*", string:serv))
{
  security_hole(port);
}
