#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# based on work from Tenable Network Security
#
# Ref: Alexandru Matei
#

# Changes by Tenable:
# - Revised plugin title (3/30/2009)


include("compat.inc");

if (description) {
  script_id(14715);
  script_version ("$Revision: 1.6 $"); 
  script_cve_id("CVE-2004-0004");
  script_bugtraq_id(9435);
  script_xref(name:"OSVDB", value:"3615");

  script_name(english:"OpenCA crypto-utils.lib libCheckSignature Function Signature Validation Weakness");

 script_set_attribute(attribute:"synopsis", value:
"A remote application is vulnerable to signature verification bypass." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.1.6 contains 
a flaw that may lead an attacker to bypass signature verification of a 
certificate." );
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

if ( egrep(pattern:"^0\.([0-8]\.|9\.(0|1$|1\.[1-6][^0-9]))", string:version) ) security_hole(port);

