#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17195);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2004-1029");
 script_bugtraq_id(11726);
 script_xref(name:"IAVA", value:"2004-b-0015");
 script_xref(name:"OSVDB", value:"12095");

 script_name(english:"Mac OS X Java JRE Plug-in Capability Arbitrary Package Access (Security Update 2005-002)");
 script_summary(english:"Check for Security Update 2005-002");
 
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
     "The remote host is missing Security Update 2005-002. This security\n",
     "update contains a security bugfix for Java 1.4.2.\n",
     "\n",
     "A vulnerability in the Java Plug-in may allow an untrusted applet to\n",
     "escalate privileges, through JavaScript calling into Java code,\n",
     "including reading and writing files with the privileges of the user\n",
     "running the applet.  Releases prior to Java 1.4.2 on Mac OS X are not\n",
     "affected by this vulnerability."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA22931"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-002."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.7 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[78]\.)", string:uname) )
{
  if ( egrep(pattern:"^Java142\.pkg", string:packages) &&
      !egrep(pattern:"^SecUpd(Srvr)?2005-002", string:packages) ) security_warning(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.(9\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2004-1029", value:TRUE);
}
