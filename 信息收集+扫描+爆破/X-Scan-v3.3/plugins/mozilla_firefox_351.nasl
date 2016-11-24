#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39853);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2467", "CVE-2009-2477");
  script_bugtraq_id(35660,35767);
  script_xref(name:"OSVDB", value:"55846");
  script_xref(name:"OSVDB", value:"56227");

  script_name(english:"Firefox < 3.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is 
affected by multiple flaws." );

  script_set_attribute(attribute:"description", value:
"Firefox 3.5 is installed on the remote host.  This version is
potentially affected by multiple flaws :

  - It may be possible to crash the browser or potentially
    execute arbitrary code by using a flash object that
    presents a slow script dialog. (MFSA 2009-35)

  - In certain cases after a return from a native function,
    such as escape(), the Just-in-Time (JIT) compiler could
    get into a corrupt state. An attacker who is able to
    trick a user of the affected software into visiting a
    malicious link may be able to leverage this issue to
    run arbitrary code subject to the user's privileges.
    (MFSA 2009-41)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-35.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-41.html" );
  script_set_attribute(attribute:"solution", value: "Upgrade to Firefox 3.5.1 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

  script_set_attribute(attribute:"vuln_publication_date",  value:"2009/07/13");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date",  value:"2009/07/17");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (ver[0] == 3 && ver[1] == 5 && ver[2] < 1)
  security_hole(get_kb_item("SMB/transport"));
