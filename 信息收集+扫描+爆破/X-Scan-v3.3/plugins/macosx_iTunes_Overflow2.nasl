#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18214);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2005-1248");
 script_bugtraq_id(13565);
 script_xref(name:"OSVDB", value:"16243");

 script_name(english:"iTunes < 4.8.0 MPEG-4 Parsing Overflow (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iTunes which is older than
version 4.8.0. Such versions reportedly fail to perform certain 
validation checks on MPEG4 files, and hence it could be possible 
to trigger a buffer overflow condition. Successful exploitation of 
this issue could lead to a denial of service condition or arbitrary
code execution on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/8545" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 4.8.0" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check the version of iTunes");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_iTunes_Overflow.nasl");
 script_require_keys("iTunes/Version");
 exit(0);
}


version = get_kb_item("iTunes/Version");
if ( ! version ) exit(0);
if ( egrep(pattern:"^4\.([0-7]\..*)$", string:version )) security_hole(0); 
