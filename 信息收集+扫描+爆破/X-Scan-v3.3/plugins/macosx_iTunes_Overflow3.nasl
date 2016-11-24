#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(21781);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2006-1467");
 script_bugtraq_id(18730);
 script_xref(name:"OSVDB", value:"26909");

 script_name(english:"iTunes < 6.0.5 AAC File Integer Overflow Vulnerability  (Mac OS X)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a remote
code execution flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iTunes, a popular jukebox program. 

The remote version of this software is vulnerable to an integer
overflow when it parses specially crafted AAC files which may lead to
the execution of arbitrary code. 

An attacker may exploit this flaw by sending a malformed AAC file to a
user on the remote host and wait for him to play it with iTunes." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10781" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 6.0.5 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Check the version of iTunes");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("macosx_iTunes_Overflow.nasl");
 script_require_keys("iTunes/Version");
 exit(0);
}


version = get_kb_item("iTunes/Version");
if ( ! version ) exit(0);
if ( egrep(pattern:"^([1-5]\..*|6\.0($|\.[0-4]$))", string:version )) security_warning(0);
