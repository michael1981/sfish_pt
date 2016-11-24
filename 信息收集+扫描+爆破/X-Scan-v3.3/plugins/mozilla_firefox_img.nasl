#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15712);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2005-0141", "CVE-2005-0143", "CVE-2005-0144", "CVE-2005-0145", "CVE-2005-0146",
               "CVE-2005-0147", "CVE-2005-0150");
 script_bugtraq_id(11648,12407);
 script_xref(name:"OSVDB", value:"13331");
 script_xref(name:"OSVDB", value:"13332");
 script_xref(name:"OSVDB", value:"13334");
 script_xref(name:"OSVDB", value:"13335");
 script_xref(name:"OSVDB", value:"13336");
 script_xref(name:"OSVDB", value:"13337");
 script_xref(name:"OSVDB", value:"13338");

 script_name(english:"Firefox < 1.0.0 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Firefox");
 
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
     "The installed version of Firefox is earlier than 1.0.0.  Such\n",
     "versions have multiple vulnerabilities that could result in\n",
     "a denial of service, local file disclosure, or password\n",
     "disclosure.  These vulnerabilities are due to the fact that\n",
     "Firefox does handle the <IMG> tag correctly."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 1.0.0 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (ver[0] < 1) security_warning(get_kb_item("SMB/transport"));
