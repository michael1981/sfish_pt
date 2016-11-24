#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(20249);
 script_version ("$Revision: 1.11 $");

 if (NASL_LEVEL >= 3000)
 {
  script_cve_id("CVE-2005-1993", "CVE-2005-2088", "CVE-2005-2272", "CVE-2005-2491", "CVE-2005-2700",
                "CVE-2005-2757", "CVE-2005-2969", "CVE-2005-3185", "CVE-2005-3700", "CVE-2005-3701",
                "CVE-2005-3702", "CVE-2005-3704", "CVE-2005-3705");
  script_bugtraq_id(13993, 14011, 14106, 14620, 14721, 15071, 15102, 16882, 16903, 16904, 16926, 29011);
  script_xref(name:"OSVDB", value:"17396");
  script_xref(name:"OSVDB", value:"17738");
  script_xref(name:"OSVDB", value:"20011");
  script_xref(name:"OSVDB", value:"21271");
  script_xref(name:"OSVDB", value:"21272");
  script_xref(name:"OSVDB", value:"21273");
  script_xref(name:"OSVDB", value:"21274");
  script_xref(name:"OSVDB", value:"21275");
  script_xref(name:"OSVDB", value:"21276");
  script_xref(name:"OSVDB", value:"21277");
 }

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-009)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a vendor supplied patch." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks 
Security Update 2005-009. 

This security update contains fixes for the following
applications :

- Apache2 
- Apache_mod_ssl 
- CoreFoundation
- curl
- iodbcadmintool
- OpenSSL
- passwordserver 
- Safari
- sudo
- syslog" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302847" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2005009tigerclient.html
http://www.apple.com/support/downloads/securityupdate2005009tigerserver.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate2005009pantherclient.html
http://www.apple.com/support/downloads/securityupdate2005009pantherserver.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for Security Update 2005-009");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-3]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2005-009|2006-00[123467]|2007-003)", string:packages)) security_hole(0);
}
