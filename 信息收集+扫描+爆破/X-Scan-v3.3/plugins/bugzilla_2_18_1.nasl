#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18654);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2173", "CVE-2005-2174");
  script_bugtraq_id(14198, 14200);
  script_xref(name:"OSVDB", value:"17801");
  script_xref(name:"OSVDB", value:"17800");

  script_name(english:"Bugzilla <= 2.18.1 / 2.19.3 Multiple Vulnerabilities (ID, more)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from
information disclosure vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host reportedly allows any user to change any flag on a bug,
even if they don't otherwise have access to the bug or rights to make
changes to it.  In addition, a private bug summary may be visible to
users if MySQL replication is used on the backend database." );
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/2.18.1/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Bugzilla 2.18.2 / 2.20rc1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple vulnerabilities in Bugzilla <= 2.18.1 / 2.19.3");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Check the installed version.
ver = get_kb_item(string("www/", port, "/bugzilla/version"));
if (ver && ver =~ "^2\.1(7\..*|8\.[01]|9\.[0-3])") 
  security_warning(port);
