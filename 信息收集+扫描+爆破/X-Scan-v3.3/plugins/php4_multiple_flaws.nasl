#
# (C) Tenable Network Security, Inc.
#

# Ref:
# http://www.securityfocus.com/advisories/5887
# http://www.php.net/ChangeLog-4.php
#


include("compat.inc");

if(description)
{
 script_id(11850);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1396", "CVE-2003-0442");
 script_bugtraq_id(6488, 7761, 8693, 8696);
 script_xref(name:"OSVDB", value:"4758");
 script_xref(name:"OSVDB", value:"14530");
 script_xref(name:"RHSA", value:"RHSA-2003:204-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:0009");

 script_name(english:"PHP < 4.3.3 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP which is older than 4.3.3.

All version of PHP 4 older than 4.3.3 contains multiple integer
overflow vulnerabilities that may allow an attacker to execute
arbitrary commands on this host.  Another problem may also invalidate
safe_mode." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-4.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.3" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);

 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 php = get_php_version(banner:banner);
 if ( ! php ) exit(0);
 if(ereg(pattern:"PHP/4\.([0-2]\..*|3\.[0-2])[^0-9]", string:php))
   security_hole(port);
