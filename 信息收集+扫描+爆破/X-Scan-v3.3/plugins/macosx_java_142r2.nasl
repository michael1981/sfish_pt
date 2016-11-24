#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(19702);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2005-2527", "CVE-2005-2528", "CVE-2005-2529", "CVE-2005-2530", "CVE-2005-2738");
 script_bugtraq_id(14825, 14826, 14827);
 script_xref(name:"OSVDB", value:"19393");
 script_xref(name:"OSVDB", value:"19394");
 script_xref(name:"OSVDB", value:"19395");
 script_xref(name:"OSVDB", value:"19396");
 script_xref(name:"OSVDB", value:"19397");

 script_name(english:"Mac OS X : Java for Mac OS X 1.3.1 and 1.4.2 Release 2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security bugfix for Java 1.4.2 and 1.3.1. 

This update fixes several security vulnerabilities that may allow a
Java applet to escalate its privileges. 

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302265" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302266" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java 1.3.1 / 1.4.2 Release 2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"Check for Java 1.4.2");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# Mac OS X 10.3.9 and 10.4.2 only
if ( egrep(pattern:"Darwin.* 7\.[0-9]\.", string:uname) )
{
  if ( !egrep(pattern:"^JavaSecurityUpdate4\.pkg", string:packages) ) security_hole(0);
}
else if ( egrep(pattern:"Darwin.* 8\.[0-2]\.", string:uname) )
{
  if ( !egrep(pattern:"^Java131and142Release2\.pkg", string:packages) ) security_hole(0);
}
