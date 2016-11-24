#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(22476);
 script_version ("$Revision: 1.10 $");
 if ( NASL_LEVEL >= 3000 )
 script_cve_id("CVE-2006-4390", "CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588", "CVE-2006-4640", 
               "CVE-2006-4391", "CVE-2006-4392", "CVE-2006-4397", "CVE-2006-4393", "CVE-2006-4394", 
               "CVE-2006-4387", "CVE-2006-4395", "CVE-2006-1721", "CVE-2006-3946", "CVE-2006-4399");
 script_bugtraq_id(20271);

 if ( NASL_LEVEL >= 3000 )
 {
  script_xref(name:"OSVDB", value:"29267");
  script_xref(name:"OSVDB", value:"29268");
  script_xref(name:"OSVDB", value:"29269");
  script_xref(name:"OSVDB", value:"29270");
  script_xref(name:"OSVDB", value:"29271");
  script_xref(name:"OSVDB", value:"29272");
  script_xref(name:"OSVDB", value:"29273");
  script_xref(name:"OSVDB", value:"29274");
  # nb: 29275 is invalid
  script_xref(name:"OSVDB", value:"29276");
  script_xref(name:"OSVDB", value:"28734");
  script_xref(name:"OSVDB", value:"28733");
  script_xref(name:"OSVDB", value:"28732");
  script_xref(name:"OSVDB", value:"27534");
  script_xref(name:"OSVDB", value:"27113");
  script_xref(name:"OSVDB", value:"24510");
}

 script_name(english:"Mac OS X < 10.4.8 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.8.

Mac OS X 10.4.8 contains several security fixes for the following 
programs :

 - CFNetwork
 - Flash Player
 - ImageIO
 - Kernel
 - LoginWindow
 - Preferences
 - QuickDraw Manager
 - SASL
 - WebCore
 - Workgroup Manager" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304460" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.4.8 :
http://www.apple.com/support/downloads/macosx1048updateintel.html
http://www.apple.com/support/downloads/macosx1048updateppc.html
http://www.apple.com/support/downloads/macosxserver1048update.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-7]([^0-9]|$))", string:os)) security_hole(0);
