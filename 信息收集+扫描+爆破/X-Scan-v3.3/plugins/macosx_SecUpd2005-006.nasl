#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18437);
 script_version ("$Revision: 1.6 $");

 if (NASL_LEVEL >= 3000)
 {
  script_cve_id("CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043", "CVE-2005-1333",
                "CVE-2005-1343", "CVE-2005-1720", "CVE-2005-1721", "CVE-2005-1722", "CVE-2005-1723",
                "CVE-2005-1724", "CVE-2005-1725", "CVE-2005-1726", "CVE-2005-1727", "CVE-2005-1728");
 }
 script_bugtraq_id(13491, 13899);
 script_xref(name:"OSVDB", value:"16074");
 script_xref(name:"OSVDB", value:"16085");
 script_xref(name:"OSVDB", value:"17263");
 script_xref(name:"OSVDB", value:"17265");
 script_xref(name:"OSVDB", value:"17266");
 script_xref(name:"OSVDB", value:"17267");
 script_xref(name:"OSVDB", value:"17268");
 script_xref(name:"OSVDB", value:"17269");
 script_xref(name:"OSVDB", value:"17270");
 script_xref(name:"OSVDB", value:"17271");
 script_xref(name:"OSVDB", value:"17272");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-006)");
 script_summary(english:"Check for Security Update 2005-006");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is missing a Mac OS X update that fixes a security\n",
     "issue."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is missing Security Update 2005-006. This security\n",
     "update contains security fixes for the following application :\n",
     "\n",
     "- AFP Server\n",
     "- Bluetooth\n",
     "- CoreGraphics\n",
     "- Folder Permissions\n",
     "- launchd\n",
     "- LaunchServices\n",
     "- NFS\n",
     "- PHP\n",
     "- VPN\n",
     "\n",
     "These programs have multiple vulnerabilities, some of which may lead\n",
     "to arbitrary code execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA23304"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-006."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.4.1
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[01]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-006", string:packages)) security_hole(0);
}
