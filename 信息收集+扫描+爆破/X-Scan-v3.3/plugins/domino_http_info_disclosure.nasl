#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19309);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2428");
  script_bugtraq_id(14388, 14389);
  script_xref(name:"OSVDB", value:"18462");

  script_name(english:"IBM Lotus Domino HTML Hidden Field Encrypted Password Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple information disclosure
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Lotus Domino Server that is
prone to several information disclosure vulnerabilities. 
Specifically, users' password hashes and other data are included in
hidden fields in the public address book 'names.nsf' readable by
default by all users.  Moreover, Domino does not use a 'salt' to
compute password hashes, which makes it easier to crack passwords." );
 script_set_attribute(attribute:"see_also", value:"http://www.cybsec.com/vuln/default_configuration_information_disclosure_lotus_domino.pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino Server version 6.0.6 / 6.5.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

  script_summary(english:"Checks for information disclosure vulnerabilities in Lotus Domino Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Check the version number in the banner.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(string:banner, pattern:"^Server: +Lotus-Domino/([0-5]\.|6\.(0\.[0-5]|[1-4]\.|5\.[0-4]))")
) {
  security_warning(port);
}
