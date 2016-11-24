#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17661);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0386");
  script_bugtraq_id(12945);
  script_xref(name:"OSVDB", value:"15157");

  script_name(english:"Mailreader network.cgi enriched/richtext MIME Message XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is vulnerable to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Mailreader installed on the
remote host is affected by a remote HTML injection vulnerability due
to its failure to properly sanitize messages using a 'text/enriched'
or 'text/richtext' MIME type.  An attacker can exploit this flaw by
sending a specially crafted message to a user who reads his mail with
Mailreader.  Then, when the user reads that message, malicious HTML or
script code embedded in the message will be run by the user's browser
in the context of the remote host, enabling the attacker to steal
authentication cookies as well as perform other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2005/dsa-700" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mailreader 2.3.36 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for remote HTML injection vulnerability in Mailreader";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Search for Mailreader.
foreach dir (cgi_dirs()) {
  # Run the main script.
  r = http_send_recv3(method: "GET", item:string(dir, "/nph-mr.cgi"), port:port);
  if (isnull(r)) exit(0);

  # Check the version number.
  if (egrep(pattern:">Mailreader.com v([01]\..*|2\.([012]\..*|3\.([012].*|3[0-5]))) ", string: r[2])) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
