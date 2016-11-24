#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12642);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-0648");
 script_bugtraq_id(10681);
 script_xref(name:"OSVDB", value:"7595");

 script_name(english:"Mozilla Browsers shell: URI Arbitrary Command Execution");
 script_summary(english:"Determines the version of Mozilla/Firefox");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that is affected by\n",
     "a command execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using Mozilla and/or Firefox, a web browser.\n",
     "The remote version of this software contains a weakness which may\n",
     "allow an attacker to execute arbitrary commands on the remote host."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-07/0376.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-07/0311.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://mozilla.org/security/shell.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla 1.7.1 / Firefox 0.9.2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
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
        (ver[1] == 7 && ver[2] == 0 && ver[3] < 1)
      )
    )
  )  security_hole(get_kb_item("SMB/transport"));
}

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (!isnull(ver))
{
  if (
    ver[0] == 0 &&
    (
      ver[1] < 9 ||
      (ver[1] == 9 && ver[2] < 2)
    )
  ) security_hole(get_kb_item("SMB/transport"));
}
