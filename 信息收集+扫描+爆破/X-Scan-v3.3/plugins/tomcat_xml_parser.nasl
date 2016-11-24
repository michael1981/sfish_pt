#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39479);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-0783");
  script_bugtraq_id(35416);
  script_xref(name:"Secunia", value:"35326");
  script_xref(name:"Secunia", value:"35344");
  script_xref(name:"OSVDB", value:"55056");

  script_name(english:"Apache Tomcat Cross-Application File Manipulation");
  script_summary(english:"Checks the Tomcat version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The web server running on the remote host has an information\n",
      "disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its self-reported version number, the remote host is\n",
      "running a vulnerable version of Apache Tomcat.  Affected versions\n",
      "permit a web application to replace the XML parser used to process\n",
      "the XML and TLD files of other applications.  This could allow a\n",
      "malicious web app to read or modify 'web.xml', 'context.xml', or TLD\n",
      "files of arbitrary web applications."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=29936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/504090"
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
    value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (report_paranoia < 2)
  exit(1, "Report paranoia is low, and this plugin's prone to false positives");

port = get_kb_item("Services/www");
if (!port) port = 8080;

version = get_kb_item("tomcat/" + port + "/error_version");
if (isnull(version))
  exit(1, "Tomcat version was not found in the KB for port " + port);

ver_fields = split(version, sep:'.', keep:FALSE);
major = ver_fields[0];
minor = ver_fields[1];
rev = ver_fields[2];

# Affects:
# 6.0.0-6.0.18 (6.0.19 is not vulnerable, but never became an official release)
# 5.5.0-5.5.27 (and 5.0.x, unsupported)
# 4.1.0-4.1.39 (and 4.0.x, unsupported)
if (
  (major == 6 && minor == 0 && rev <= 18) ||
  (major == 5 && minor == 5 && rev <= 27) ||
  (major == 5 && minor == 0) ||
  (major == 4 && minor == 1 && rev <= 39) ||
  (major == 4 && minor == 0)
) security_note(port);
else exit(1, "Version " + version + " is not vulnerable");

