#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17604);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2005-0255", "CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0578",
               "CVE-2005-0586", "CVE-2005-0587", "CVE-2005-0588", "CVE-2005-0590",
               "CVE-2005-0592", "CVE-2005-0593");
 script_bugtraq_id(12659, 12881, 12885);
 script_xref(name:"OSVDB", value:"14185");
 script_xref(name:"OSVDB", value:"14187");
 script_xref(name:"OSVDB", value:"14188");
 script_xref(name:"OSVDB", value:"14189");
 script_xref(name:"OSVDB", value:"14191");
 script_xref(name:"OSVDB", value:"14192");
 script_xref(name:"OSVDB", value:"14193");
 script_xref(name:"OSVDB", value:"14194");
 script_xref(name:"OSVDB", value:"14195");
 script_xref(name:"OSVDB", value:"14198");
 script_xref(name:"OSVDB", value:"14937");
 script_xref(name:"OSVDB", value:"15010");

 script_name(english:"Mozilla Browser < 1.7.6 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host contains multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mozilla contains various security issues which
may allow an attacker to impersonate a website and to trick a user
into accepting and executing arbitrary files or to cause a heap
overflow in the FireFox process and execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of Mozilla");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Version");
 exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 7 ||
      (ver[1] == 7 && ver[2] < 6)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
