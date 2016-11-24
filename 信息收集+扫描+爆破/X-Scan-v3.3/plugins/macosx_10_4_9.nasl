#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3004 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(24811);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2007-0719", "CVE-2007-0467", "CVE-2007-0720", "CVE-2007-0721", "CVE-2007-0722", 
               "CVE-2006-6061", "CVE-2006-6062", "CVE-2006-5679", "CVE-2007-0229", "CVE-2007-0267", 
               "CVE-2007-0299", "CVE-2007-0723", "CVE-2006-5330", "CVE-2006-0300", "CVE-2006-6097", 
               "CVE-2007-0318", "CVE-2007-0724", "CVE-2007-1071", "CVE-2007-0733", "CVE-2006-5836", 
               "CVE-2006-6129", "CVE-2006-6173", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-2753", 
               "CVE-2006-3081", "CVE-2006-4031", "CVE-2006-4226", "CVE-2006-3469", "CVE-2006-6130", 
               "CVE-2007-0236", "CVE-2007-0726", "CVE-2006-0225", "CVE-2006-4924", "CVE-2006-5051", 
               "CVE-2006-5052", "CVE-2007-0728", "CVE-2007-0588", "CVE-2007-0730", "CVE-2007-0731", 
               "CVE-2007-0463", "CVE-2005-2959", "CVE-2006-4829");
 script_bugtraq_id(20982, 21236, 21291, 21349, 22041, 22948);
 script_xref(name:"OSVDB", value:"20303");
 script_xref(name:"OSVDB", value:"22692");
 script_xref(name:"OSVDB", value:"23371");
 script_xref(name:"OSVDB", value:"25226");
 script_xref(name:"OSVDB", value:"25228");
 script_xref(name:"OSVDB", value:"25987");
 script_xref(name:"OSVDB", value:"27054");
 script_xref(name:"OSVDB", value:"27416");
 script_xref(name:"OSVDB", value:"27703");
 script_xref(name:"OSVDB", value:"28012");
 script_xref(name:"OSVDB", value:"28834");
 script_xref(name:"OSVDB", value:"29152");
 script_xref(name:"OSVDB", value:"29264");
 script_xref(name:"OSVDB", value:"29266");
 script_xref(name:"OSVDB", value:"29863");
 script_xref(name:"OSVDB", value:"30196");
 script_xref(name:"OSVDB", value:"30216");
 script_xref(name:"OSVDB", value:"30509");
 script_xref(name:"OSVDB", value:"30510");
 script_xref(name:"OSVDB", value:"30706");
 script_xref(name:"OSVDB", value:"30721");
 script_xref(name:"OSVDB", value:"30722");
 script_xref(name:"OSVDB", value:"30723");
 script_xref(name:"OSVDB", value:"31653");
 script_xref(name:"OSVDB", value:"32684");
 script_xref(name:"OSVDB", value:"32685");
 script_xref(name:"OSVDB", value:"32686");
 script_xref(name:"OSVDB", value:"32687");
 script_xref(name:"OSVDB", value:"32703");
 script_xref(name:"OSVDB", value:"32706");
 script_xref(name:"OSVDB", value:"33365");
 script_xref(name:"OSVDB", value:"34072");
 script_xref(name:"OSVDB", value:"34845");
 script_xref(name:"OSVDB", value:"34846");
 script_xref(name:"OSVDB", value:"34847");
 script_xref(name:"OSVDB", value:"34848");
 script_xref(name:"OSVDB", value:"34849");
 script_xref(name:"OSVDB", value:"34850");
 script_xref(name:"OSVDB", value:"34851");
 script_xref(name:"OSVDB", value:"34852");
 script_xref(name:"OSVDB", value:"34853");
 script_xref(name:"OSVDB", value:"34854");
 script_xref(name:"OSVDB", value:"34855");

 script_name(english:"Mac OS X < 10.4.9 Multiple Vulnerabilities (Security Update 2007-003)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.9 or a version of Mac OS X 10.3 which does not have 
Security Update 2007-003 applied.

This update contains several security fixes for the following programs :

 - ColorSync
 - CoreGraphics
 - Crash Reporter
 - CUPS
 - Disk Images
 - DS Plugins
 - Flash Player
 - GNU Tar
 - HFS
 - HID Family
 - ImageIO
 - Kernel
 - MySQL server
 - Networking
 - OpenSSH
 - Printing
 - QuickDraw Manager
 - servermgrd
 - SMB File Server
 - Software Update
 - sudo 
 - WebLog" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305214" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 : Upgrade to Mac OS X 10.4.9 :

http://www.apple.com/support/downloads/macosxserver1049updateppc.html
http://www.apple.com/support/downloads/macosx1049updateintel.html
http://www.apple.com/support/downloads/macosxserver1049updateuniversal.html

Mac OS X 10.3 : Apply Security Update 2007-003 :

http://www.apple.com/support/downloads/securityupdate20070031039client.html
http://www.apple.com/support/downloads/securityupdate20070031039server.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	 os = get_kb_item("Host/OS");
	 confidence = get_kb_item("Host/OS/Confidence");
	 if ( confidence <= 90 ) exit(0);
	}
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-8]([^0-9]|$))", string:os)) security_hole(0);
else if ( ereg(pattern:"Mac OS X 10\.3\.", string:os) )
{
 packages = get_kb_item("Host/MacOSX/packages");
 if ( ! packages ) exit(0);
 if (!egrep(pattern:"^SecUpd(Srvr)?2007-003", string:packages)) security_hole(0);
}
