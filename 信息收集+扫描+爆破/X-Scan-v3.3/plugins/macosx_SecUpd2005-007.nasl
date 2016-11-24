#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3004) exit(0);

include("compat.inc");

if(description)
{
 script_id(19463);
 script_version ("$Revision: 1.4 $");

 script_cve_id("CVE-2005-1344", "CVE-2004-0942", "CVE-2004-0885", "CVE-2004-1083", "CVE-2004-1084",
               "CVE-2005-2501", "CVE-2005-2502", "CVE-2005-2503", "CVE-2005-2504", "CVE-2005-2505",
               "CVE-2005-2506", "CVE-2005-2525", "CVE-2005-2526", "CVE-2005-2507", "CVE-2005-2508",
               "CVE-2005-2519", "CVE-2005-2513", "CVE-2004-1189", "CVE-2005-1174", "CVE-2005-1175",
               "CVE-2005-1689", "CVE-2005-2511", "CVE-2005-2509", "CVE-2005-2512", "CVE-2005-2745",
               "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711", "CVE-2004-0079", "CVE-2004-0112",
               "CVE-2005-2514", "CVE-2005-2515", "CVE-2005-2516", "CVE-2005-2517", "CVE-2005-2524",
               "CVE-2005-2520", "CVE-2005-2518", "CVE-2005-2510", "CVE-2005-1769", "CVE-2005-2095",
               "CVE-2005-2521", "CVE-2005-2522", "CVE-2005-2523", "CVE-2005-0605", "CVE-2005-2096",
               "CVE-2005-1849");
 script_bugtraq_id(14567, 14569);
 script_xref(name:"OSVDB", value:"18774");
 script_xref(name:"OSVDB", value:"18775");
 script_xref(name:"OSVDB", value:"18776");
 script_xref(name:"OSVDB", value:"18777");
 script_xref(name:"OSVDB", value:"18778");
 script_xref(name:"OSVDB", value:"18779");
 script_xref(name:"OSVDB", value:"18780");
 script_xref(name:"OSVDB", value:"18781");
 script_xref(name:"OSVDB", value:"18782");
 script_xref(name:"OSVDB", value:"18783");
 script_xref(name:"OSVDB", value:"18784");
 script_xref(name:"OSVDB", value:"18785");
 script_xref(name:"OSVDB", value:"18786");
 script_xref(name:"OSVDB", value:"18787");
 script_xref(name:"OSVDB", value:"18788");
 script_xref(name:"OSVDB", value:"18789");
 script_xref(name:"OSVDB", value:"18790");
 script_xref(name:"OSVDB", value:"18791");
 script_xref(name:"OSVDB", value:"18792");
 script_xref(name:"OSVDB", value:"18793");
 script_xref(name:"OSVDB", value:"18794");
 script_xref(name:"OSVDB", value:"18795");
 script_xref(name:"OSVDB", value:"18796");
 script_xref(name:"OSVDB", value:"18797");
 script_xref(name:"OSVDB", value:"18983");
 script_xref(name:"OSVDB", value:"19705");
 script_xref(name:"OSVDB", value:"19709");

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-007)");
 script_summary(english:"Check for Security Update 2005-007");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote host is missing a Mac OS X update that fixes various\n",
   "security issues."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
  "The remote host is running a version of Mac OS X 10.4 or 10.3 that\n",
  "does not have Security Update 2005-007 applied.\n",
  "\n",
  "This security update contains fixes for the following products :\n",
  "\n",
  "  - Apache 2\n",
  "  - AppKit\n",
  "  - Bluetooth\n",
  "  - CoreFoundation\n",
  "  - CUPS\n",
  "  - Directory Services\n",
  "  - HItoolbox\n",
  "  - Kerberos\n",
  "  - loginwindow\n",
  "  - Mail\n",
  "  - MySQL\n",
  "  - OpenSSL\n",
  "  - QuartzComposerScreenSaver\n",
  "  - ping\n",
  "  - Safari\n",
  "  - SecurityInterface\n",
  "  - servermgrd\n",
  "  - servermgr_ipfilter\n",
  "  - SquirelMail\n",
  "  - traceroute\n",
  "  - WebKit\n",
  "  - WebLog Server\n",
  "  - X11\n",
  "  - zlib"
  )
 );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://docs.info.apple.com/article.html?artnum=302163"
  );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Install Security Update 2005-007."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.4.2
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.2\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-007", string:packages)) security_hole(0);
}
