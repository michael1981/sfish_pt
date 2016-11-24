#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39447);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-5515");
  script_bugtraq_id(35263);
  script_xref(name:"OSVDB", value:"55053");
  script_xref(name:"Secunia", value:"35326");

  script_name(english:"Apache Tomcat RequestDispatcher Directory Traversal Vulnerability");
  script_summary(english:"Checks the version retrieved from a Tomcat error page");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is affected by a directory traversal\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its self-reported version number, the remote host is\n",
      "running a vulnerable version of Apache Tomcat.  Due to a bug in a\n",
      "RequestDispatcher API, target paths are normalized before the query\n",
      "string is removed, which could result in directory traversal attacks.\n",
      "This could allow a remote attacker to view files outside of the web\n",
      "application's root."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.fujitsu.com/global/support/software/security/products-f/interstage-200902e.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=tomcat-user&m=124449799021571&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-6.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-4.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to versions 6.0.20 / 5.5.SVN / 4.1.SVN or later, or apply the\n",
      "patches referenced in the vendor advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (report_paranoia < 2)
  exit(1, "Report paranoia is low, and this plugin's prone to false positives");

port = get_http_port(default:8080, embedded: 0);

version = get_kb_item("tomcat/" + port + "/error_version");
if (isnull(version))
  exit(1, "Tomcat version was not found in the KB for port " + port);

ver_fields = split(version, sep:'.', keep:FALSE);
major = ver_fields[0];
minor = ver_fields[1];
rev = ver_fields[2];

# Affects:
# 6.0.0-6.0.18 (6.0.19 is not vulnerable, but never became an official release)
# 5.5.0-5.5.27
# 4.1.0-4.1.39
if (
  (major == 6 && minor == 0 && rev <= 18) ||
  (major == 5 && minor == 5 && rev <= 27) ||
  (major == 4 && minor == 1 && rev <= 39)
) security_warning(port);
else exit(1, "Version " + version + " is not vulnerable");
