#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18521);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2005-1579");
 script_bugtraq_id(13603);
 script_xref(name:"OSVDB", value:"16376");

 script_name(english:"Quicktime < 7.0.1 Quartz Composer Information Disclosure (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime 7 which is
older than Quicktime 7.0.1. The remote version of this software is 
vulnerable to an information disclosure flaw when handling Quartz 
Composer files which may leak data to an arbitrary web location.

To exploit this flaw, an attacker would need to lure a user on the 
remote host into viewing a specially crafted Quartz Composer object." );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2005/May/msg00006.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/8642" );
 script_set_attribute(attribute:"solution", value:
"Install Quicktime 7.0.1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Check for Quicktime 7.0.1");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if ( ! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( int(version[0]) == 7 && int(version[1]) == 0 && int(version[2]) == 0 ) 
  security_warning(0);
