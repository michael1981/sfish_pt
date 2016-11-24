#
# (C) Tenable Network Security, Inc
#

# Message-ID: <20030317202237.3654.qmail@www.securityfocus.com>
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-010] Path Disclosure & Cross Site Scripting Vulnerability in MyABraCaDaWeb



include("compat.inc");

if (description)
{
 script_id(11417);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2003-1548", "CVE-2003-1549");
 script_bugtraq_id(7126, 7127);
 script_xref(name:"OSVDB", value:"42687");
 script_xref(name:"OSVDB", value:"54590");

 script_name(english:"MyAbraCadaWeb header.php ma_kw Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI which is vulnerable to a cross-
site scripting and a path disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running MyAbraCadaWeb.  An attacker may
use it to perform a cross-site scripting attack on this host, or to
reveal the full path to its physical location by sending a malformed
request." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

test_cgi_xss(dirs: cgi_dirs(), cgi: "/index.php", 
 pass_str: "<script>alert(document.cookie)</script>",
 qs: "module=pertinance&ma_ou=annuaire2liens&ma_kw=<script>alert(document.cookie)</script>");
