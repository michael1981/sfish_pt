#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14729);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904");
 script_bugtraq_id(11174, 11171, 11170);
 script_xref(name:"OSVDB", value:"9966");
 script_xref(name:"OSVDB", value:"9968");
 script_xref(name:"OSVDB", value:"10525");
 script_xref(name:"OSVDB", value:"10526");
 script_xref(name:"OSVDB", value:"10527");
 script_xref(name:"OSVDB", value:"10528");

 script_name(english:"Mozilla Firefox / Thunderbird Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla and/or Thunderbird, an 
alternative mail user agent.

The remote version of this software is vulnerable to 
several flaws which may allow an attacker to execute 
arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a 
rogue email to a victim on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.3 or Thunderbird 0.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of Mozilla");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Thunderbird/Version");
 exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (!isnull(ver))
{
  if (
    ver[0] < 1 ||
    (
      ver[0] == 1 &&
      (
        ver[1] < 7 ||
        (ver[1] == 7 && ver[2] < 3)
      )
    )
  )  security_hole(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (!isnull(ver))
{
  if (ver[0] == 0 && ver[1] < 8)
    security_hole(get_kb_item("SMB/transport"));
}
