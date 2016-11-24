#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# based on work from Tenable Network Security
#
# Ref: Chris Covell and Gottfried Scheckenbach
#


include("compat.inc");

if (description) {
  script_id(14714);
  script_version ("$Revision: 1.4 $"); 
  script_cve_id("CVE-2003-0960");
  script_bugtraq_id(9123);
  script_xref(name:"OSVDB", value:"2884");

  script_name(english:"OpenCA Multiple Signature Validation Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.1.3 contains 
multiple flaws that may allow revoked or expired certificates to be 
accepted as valid." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  summary["english"] = "Checks for the version of OpenCA";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("openca_html_injection.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

version = get_kb_item("www/" + port + "/openca/version");
if ( ! version ) exit(0);


if ( egrep(pattern:"(0\.[0-8]\.|0\.9\.(0|1$|1\.[1-3][^0-9]))", string:version) ) security_hole(port);

