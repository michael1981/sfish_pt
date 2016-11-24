#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14728);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0906", "CVE-2004-0908");
 script_bugtraq_id(11194, 11192, 11179, 11177, 11171, 11169 );
 script_xref(name:"OSVDB", value:"9965");
 script_xref(name:"OSVDB", value:"10559");
 script_xref(name:"OSVDB", value:"10525");
 script_xref(name:"OSVDB", value:"10524");

 script_name(english:"Mozilla / Firefox Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Mozilla");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that is affected by\n",
     "multiple vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using Mozilla and/or Firefox, a web browser.\n\n",
     "The remote version of this software is vulnerable to several flaws\n",
     "which may allow an attacker to execute arbitrary code on the remote\n",
     "host, get access to content of the user clipboard or, perform\n",
     "a cross-domain cross site scripting attack.\n\n",
     "A remote attacker could exploit these issues by tricking a user\n",
     "into viewing a malicious web page."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla 1.7.3 / Firefox 0.10.0 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencies("mozilla_org_installed.nasl");
 if ( NASL_LEVEL >= 3206 ) script_require_ports("Mozilla/Version", "Mozilla/Firefox/Version");
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

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (!isnull(ver))
{
  if (ver[0] == 0 && ver[1] < 10)
    security_hole(get_kb_item("SMB/transport"));
}
