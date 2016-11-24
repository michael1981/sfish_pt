#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(25122);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-2007-2175");
 script_bugtraq_id(23608);
 script_xref(name:"OSVDB", value:"34178");

 script_name(english:"Quicktime < 7.1.6 quicktime.util.QTHandleRef toQTPointer Method Arbitrary Code Execution (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Quicktime on the remote
Mac OS X host which contains a bug which might allow a rogue Java 
program to write anywhere in the heap.

An attacker may be able to leverage these issues to execute arbitrary 
code on the remote host by luring a victim into visiting a rogue page
containing a malicious Java applet." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305446" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Quicktime version 7.1.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for Quicktime 7.1.6");
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
     (int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 6) ) security_hole(0);
