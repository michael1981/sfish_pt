#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 15 Dec 2004 19:46:20 +0100
#  From: Stefan Esser <sesser@php.net>
#  To: bugtraq@securityfocus.com, full-disclosure@lists.netsys.com
#  Subject: Advisory 01/2004: Multiple vulnerabilities in PHP 4/5  
#


include("compat.inc");

if(description)
{
 script_id(15973);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065");
 script_bugtraq_id(11964, 11981, 11992, 12045);
 script_xref(name:"OSVDB", value:"12410");
 script_xref(name:"OSVDB", value:"12411");
 script_xref(name:"OSVDB", value:"12412");
 script_xref(name:"OSVDB", value:"12413");
 script_xref(name:"OSVDB", value:"12415");
 script_xref(name:"OSVDB", value:"12600");
 script_xref(name:"OSVDB", value:"12602");
 script_xref(name:"OSVDB", value:"34717");

 script_name(english:"PHP < 4.3.10 / 5.0.3 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP which is older than 5.0.3 or
4.3.10.

The remote version of this software is vulnerable to various security
issues which may, under certain circumstances, to execute arbitrary code
on the remote host, provided that we can pass arbitrary data to some
functions, or to bypass safe_mode." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.0.3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 5.0.3 or  4.3.10" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
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

 if(ereg(pattern:"PHP/(4\.([012]\.|3\.[0-9][^0-9])|5\.0\.[012][^0-9])", string:php))
   security_hole(port);
