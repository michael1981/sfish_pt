#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20135);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2005-2753", "CVE-2005-2754", "CVE-2005-2755", "CVE-2005-2756");
 script_bugtraq_id(15306, 15307, 15308, 15309);
 script_xref(name:"OSVDB", value:"20475");
 script_xref(name:"OSVDB", value:"20476");
 script_xref(name:"OSVDB", value:"20477");
 script_xref(name:"OSVDB", value:"20478");

 script_name(english:"Quicktime < 7.0.3 Multiple Vulnerabilities (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime may allow an attacker to execute arbitrary
code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime 7 which is older
than Quicktime 7.0.3.

The remote version of this software is vulnerable to various buffer overflows 
which may allow an attacker to execute arbitrary code on the remote host by
sending a malformed file to a victim and have him open it using QuickTime 
player." );
 script_set_attribute(attribute:"solution", value:
"Install Quicktime 7.0.3 or later." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302772" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for Quicktime 7.0.3");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( int(version[0]) == 7 && int(version[1]) == 0 && int(version[2]) < 3 ) security_warning(0);
