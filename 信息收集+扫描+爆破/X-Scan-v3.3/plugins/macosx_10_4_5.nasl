#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(20911);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2006-0382");
 script_bugtraq_id(16654);
 script_xref(name:"OSVDB", value:"23190");

 script_name(english:"Mac OS X < 10.4.5 Kernel Undocumented System Call Local DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.5.

Mac OS X 10.4.5 contains a security fix for a local denial of
service vulnerability. A malicious local user may trigger the vulnerability
by invoking an undocumented system call." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.5 :
http://www.apple.com/support/downloads/macosxupdate1045.html
http://www.apple.com/support/downloads/macosxserver1045.html" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=61798" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-4]([^0-9]|$))", string:os )) security_note(0);
