#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

# References :
# Date:  Tue, 16 Oct 2001 11:34:56 +0900
# From: "snsadv@lac.co.jp" <snsadv@lac.co.jp>
# To: bugtraq@securityfocus.com
# Subject: [SNS Advisory No.44] Trend Micro OfficeScan Corporate Edition
# (Virus Buster Corporate Edition) Configuration File Disclosure Vulnerability 
#


include("compat.inc");

if(description)
{
 script_id(11074);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-1151");
 script_bugtraq_id(3438);
 script_xref(name:"OSVDB", value:"6161");
 
 script_name(english:"Trend Micro OfficeScan ofcscan.ini Configuration File Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an 
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"Trend Micro OfficeScan Corporate Edition (Japanese version: 
Virus Buster Corporate Edition) web-based management console 
let anybody access /officescan/hotdownload without authentication.

Reading the configuration file /officescan/hotdownload/ofcscan.ini
will reveal information on your system. More, it contains passwords
that are encrypted by a weak specific algorithm; so they might be 
decrypted" );
 script_set_attribute(attribute:"solution", value:
"Upgrade OfficeScan." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 script_summary(english:"Checks for the presence of /officescan/hotdownload/ofscan.ini");

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www", 80);
 script_dependencie("http_version.nasl");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/officescan/hotdownload/ofscan.ini", port:port);

if(!isnull(res))
{
 res = http_send_recv3(method:"GET", item:"/officescan/hotdownload/nessus.ini", port:port);
 if ( res ) exit(0);
 security_warning(port);
}
