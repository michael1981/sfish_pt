#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(25554);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2007-2242");
 script_bugtraq_id(23615);
 script_xref(name:"OSVDB", value:"35303");

 script_name(english:"Mac OS X < 10.4.10 IPv6 Type 0 Route Headers DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older
than version 10.4.10. 

This update a security fix for IPv6 type 0 routing headers, which
might be abused by an attacker to consume excessive bandwidth." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305712" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.10 :

http://docs.info.apple.com/article.html?artnum=305533" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	os = get_kb_item("Host/OS");
	confidence = get_kb_item("Host/OS/Confidence");
	if ( confidence <= 90 ) exit(0);
}
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-9]([^0-9]|$))", string:os)) security_hole(0);
