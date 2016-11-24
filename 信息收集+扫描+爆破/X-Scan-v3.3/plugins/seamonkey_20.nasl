#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42307);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3372","CVE-2009-3373","CVE-2009-3376");
  script_bugtraq_id(36855, 36856, 36867);
  script_xref(name:"OSVDB", value:"59389");
  script_xref(name:"OSVDB", value:"59393");
  script_xref(name:"OSVDB", value:"59394");

  script_name(english:"SeaMonkey < 2.0");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities." );

  script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey is earlier than 2.0. Such
versions are potentially affected by the following security
issues :
   
  - Provided the browser is configured to use Proxy
    Auto-configuration it may be possible for an attacker to
    crash the browser or execute arbitrary code.
    (MFSA 2009-55)

  - Mozilla's GIF image parser is affected by a heap-based
    buffer overflow. (MFSA 2009-56)

  - If a file contains right-to-left override character 
    (RTL) in the filename it may be possible for an attacker 
    to obfuscate the filename and extension of the file 
    being downloaded. (MFSA 2009-62)" );

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-55.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-56.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 2.0 or later." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/29"
  );

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");

ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(1, "The 'SeaMonkey/Version' KB item is missing.");

if (ver[0] < 2 )
 security_hole(get_kb_item("SMB/transport"));
else
  exit(0, "No vulnerable versions of SeaMonkey were found.");
