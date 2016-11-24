#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(22335);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2006-4381", "CVE-2006-4382", "CVE-2006-4384", "CVE-2006-4385", "CVE-2006-4386",
               "CVE-2006-4388", "CVE-2006-4389");
 script_bugtraq_id(19976);
 script_xref(name:"OSVDB", value:"28768");
 script_xref(name:"OSVDB", value:"28769");
 script_xref(name:"OSVDB", value:"28770");
 script_xref(name:"OSVDB", value:"28771");
 script_xref(name:"OSVDB", value:"28772");
 script_xref(name:"OSVDB", value:"28773");
 script_xref(name:"OSVDB", value:"28774");

 script_name(english:"Quicktime < 7.1.3 Multiple Vulnerabilities (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by multiple overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime prior to
7.1.3. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304357" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Quicktime version 7.1.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check for Quicktime 7.1.3");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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
     (int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 3) ) security_warning(0);
