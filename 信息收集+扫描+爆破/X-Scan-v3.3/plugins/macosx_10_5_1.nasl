#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(28252);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2007-4702", "CVE-2007-4703", "CVE-2007-4704");
 script_bugtraq_id(26459, 26460, 26461);
 script_xref(name:"OSVDB", value:"40689");
 script_xref(name:"OSVDB", value:"40690");
 script_xref(name:"OSVDB", value:"40691");

 script_name(english:"Mac OS X < 10.5.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 which is older than
version 10.5.1.

This update contains several security fixes for the application Firewall." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.1 :


http://www.apple.com/support/downloads/macosx1051update.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307004" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	os = get_kb_item("Host/OS");
	if (! os ) exit(0);
	conf = get_kb_item("Host/OS/Confidence");
	if ( conf <= 70 ) exit(0);
	}
if ( ereg(pattern:"Mac OS X 10\.5($|\.0)", string:os)) security_warning(0);
