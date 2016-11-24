#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15408);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-2225");
 script_bugtraq_id(11311);
 script_xref(name:"OSVDB", value:"10478");

 script_name(english:"Firefox < 0.10.1 Download Directory Arbitrary File Deletion");
 script_summary(english:"Determines the version of Firefox");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a web browser that is affected by\n",
     "an arbitrary file deletion vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The installed version of Firefox is earlier than 0.10.1.  Such\n",
     "versions contain a weakness which may allow a remote attacker\n",
     "to delete arbitrary files in the user download directory.  To\n",
     "exploit this, an attacker would need to trick a user into viewing\n",
     "a malicious web page."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/press/mozilla-2004-10-01-02.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 0.10.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/version");
 script_require_ports(139, 445);
 exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] == 0 &&
  (
    ver[1] < 10 ||
    (ver[1] == 10 && ver[2] < 1)
  )
) security_warning(get_kb_item("SMB/transport"));
