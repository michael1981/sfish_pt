#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41970);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_bugtraq_id(36572, 36573);
  script_xref(name:"OSVDB", value:"57955");
  script_xref(name:"OSVDB", value:"58519");
  script_xref(name:"OSVDB", value:"58520");

  script_name(english:"Samba < 3.0.37 / 3.2.15 / 3.3.8 / 3.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Samba server may be affected by multiple vulnerabilities.")
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its banner, the version of Samba server on the remote\n",
      "host is earlier than 3.0.37 / 3.2.15 / 3.3.8 / 3.4.2.  Such versions\n",
      "are potentially affected by multiple issues :\n",
      "\n",
      "  - If a user in '/etc/passwd' is misconfigured to have an\n",
      "    empty home directory, then connecting to the home share\n",
      "    of this user will use the root of the file system as the\n",
      "    home directory. (CVE-2009-2813)\n",
      "\n",
      "  - Specially crafted SMB requests on authenticated\n",
      "    SMB connections can send smbd into a 100% loop, causing\n",
      "    a denial of service. (CVE-2009-2906)\n",
      "\n",
      "  - When 'mount.cifs' is installed as a setuid program, a\n",
      "    user can pass it a credential or password path to which\n",
      "    he or she does not have access and then use the\n",
      "    '--verbose' option to view the first line of that file.\n",
      "    (CVE-2009-2948)\n"
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2009-2906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2009-2948.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2009-2813.html"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Samba 3.0.37 / 3.2.15 / 3.3.8 / 3.4.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/01"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/01"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/02"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager");

  exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(1, "Security patches may have been backported.");

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman)) exit(1, "The 'SMB/NativeLanManager' KB item is missing.");
if ("Samba " >!< lanman) exit(0, "The host is not using Samba.");

if (
  lanman =~ "Samba 3\.0\.([0-9]|[0-2][0-9]|3[0-6])([^0-9]|$)" ||
  lanman =~ "Samba 3\.2\.([0-9]|1[0-4])([^0-9]|$)" ||
  lanman =~ "Samba 3\.3\.[0-7]([^0-9]|$)" ||
  lanman =~ "Samba 3\.4\.[01]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "The remote Samba server appears to be :\n",
      "\n",
      "  ", lanman, "\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
exit(0, "The host is not affected because " + lanman + " is installed.");
