#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(24762);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2007-0712", "CVE-2007-0713", "CVE-2007-0714", "CVE-2007-0715",
               "CVE-2007-0716", "CVE-2007-0717", "CVE-2007-0718");
 script_bugtraq_id(22827);
 script_xref(name:"OSVDB", value:"33898");
 script_xref(name:"OSVDB", value:"33899");
 script_xref(name:"OSVDB", value:"33900");
 script_xref(name:"OSVDB", value:"33901");
 script_xref(name:"OSVDB", value:"33902");
 script_xref(name:"OSVDB", value:"33903");
 script_xref(name:"OSVDB", value:"33904");

 script_name(english:"Quicktime < 7.1.5 Multiple Vulnerabilities (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Quicktime on the remote
Mac OS X host is affected by multiple buffer overflows.  An attacker
may be able to leverage these issues to crash the affected application
or to execute arbitrary code on the remote host by sending a
specially-crafted file to a victim and having him open it using
QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305149" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Quicktime version 7.1.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for Quicktime 7.1.5");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) < 7) ||
     (int(version[0]) == 7 && int(version[1]) == 0 ) ||
     (int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 5) ) security_hole(0);
