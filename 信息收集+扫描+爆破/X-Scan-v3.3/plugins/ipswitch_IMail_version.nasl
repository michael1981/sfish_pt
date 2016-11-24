#
# (C) Tenable Network Security, Inc.
#

# References:
#
# http://www.nessus.org/u?fd6d1531
#
# Date:  Sun, 10 Mar 2002 21:37:33 +0100
# From: "Obscure" <obscure@eyeonsecurity.net>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: IMail Account hijack through the Web Interface
#
#  Date:  Mon, 11 Mar 2002 04:11:43 +0000 (GMT)
# From: "Zillion" <zillion@safemode.org>
# To: "Obscure" <obscure@zero6.net>
# CC: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, "Obscure" <obscure@eyeonsecurity.net>
# Subject: Re: IMail Account hijack through the Web Interface
#



include("compat.inc");

if(description)
{
 script_id(11271);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-1286");
 script_bugtraq_id(3432); 
 script_xref(name:"OSVDB", value:"10845");
 
 script_name(english:"Ipswitch IMail Web Interface URI Referer Session Token Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IMail web interface. In this version, the
session is maintained via the URL. It will be disclosed in the 
Referer field if you receive an email with external links (e.g. images)" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-10/0082.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0100.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0101.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0128.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0158.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMail 7.06  or turn off the 'ignore source address 
in security check' option." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for version of IMail web interface");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 #script_require_keys("www/IMail");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");


port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/(([1-6]\.)|(7\.0[0-5]))", string:serv))
   security_warning(port);

