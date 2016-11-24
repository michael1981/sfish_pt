#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12255);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2004-0488");
 script_bugtraq_id(10355);
 script_xref(name:"OSVDB", value:"6472");
 
 script_name(english:"mod_ssl ssl_util_uuencode_binary Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote host is using a version of mod_ssl which is older than
2.8.18. 

This version is vulnerable to a flaw which may allow an attacker to
disable the remote web site remotely, or to execute arbitrary code on
the remote host. 

Note that several Linux distributions patched the old version of this
module.  Therefore, this alert might be a false-positive.  Please
check with your vendor to determine if you really are vulnerable to
this flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.8.18 (Apache 1.3) or to Apache 2.0.50." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for version of mod_ssl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 if ( ! defined_func("bn_random") )
 	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "redhat-RHSA-2004-245.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("backport.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( get_kb_item("CVE-2004-0488") ) exit(0);

banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner || backported )exit(0);

if ( "Darwin" >< banner )  exit(0);
 
serv = strstr(banner, "Server");

if(ereg(pattern:"Apache/1\..*mod_ssl/(1\.|2\.([0-7]\.|8\.([0-9][^0-9]|1[0-7]))).*", string:serv))
{
   security_hole(port);
}
else if(ereg(pattern:"Apache/2\..*mod_ssl/(1\.|2\.0\.([0-9][^0-9]|[0-4][0-9][^0-9]))", string:serv))
{
   security_hole(port);
}
