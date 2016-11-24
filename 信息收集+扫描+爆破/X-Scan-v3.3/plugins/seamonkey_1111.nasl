#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33506);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-2785");
  script_bugtraq_id(29802);
  script_xref(name:"OSVDB", value:"46421");

  script_name(english:"SeaMonkey < 1.1.11");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is affected by a code execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey may allow a remote attacker to
execute arbitrary code on the remote host by creating a very large
number of references to a common CSS object, which can lead to an
overflow the CSS reference counter, causing a crash when the browser
attempts to free the CSS object while still in use." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-34.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 && 
    (
      ver[1] == 0 ||
      (ver[1] == 1 && ver[2] < 11)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
