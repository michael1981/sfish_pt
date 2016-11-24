#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40986);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3025", "CVE-2009-3026");
  script_bugtraq_id(36367, 36368);
  script_xref(name:"OSVDB", value:"57521");
  script_xref(name:"OSVDB", value:"57522");

  script_name(english:"Pidgin < 2.6.1 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has an instant messaging client that is affected by \n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Pidgin installed on the remote host is earlier than\n",
      "2.6.1.  Such versions are reportedly affected by one or more of\n",
      "following issues :\n",
      "\n",
      "  - The Yahoo protocol plugin may crash when receiving an IM\n",
      "    from any user that contains a URL. (CVE-2009-3025)\n",
      "\n",
      "  - The XMPP protocol plugin can be tricked into establishing\n",
      "    an insecure connection by a malicious man in the middle by \n",
      "    causing libpurple to use the older IQ-based login and then\n",
      "    not offering TLS/SSL. (CVE-2009-3026)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=36"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=35"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.6.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/15"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/Pidgin/Version");
if (isnull(version)) exit(1, "The 'SMB/Pidgin/Version' KB item is missing.");

ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 2.6.1 are affected
if (
  major < 2 ||
  (major == 2 && minor < 6) ||
  (major == 2 && minor == 6 && rev < 1)
)
{
  port = get_kb_item("SMB/transport");

  if(report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Installed version  : ", version, "\n",
      "  Should be at least : 2.6.1\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + version + " is not affected.");

