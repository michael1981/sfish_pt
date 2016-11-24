#
# (C) Tenable Network Security, Inc.
#

# These vulnerabilities are documented as Cisco bug ID CSCec17308/CSCec19124(tftp), 
# CSCec17406(port 1080), and CSCec66884/CSCec71157(SU access).


include("compat.inc");


if(description)
{
 script_id(16202);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2002-0952", "CVE-2002-1553", "CVE-2002-1554", "CVE-2002-1555", "CVE-2002-1556", "CVE-2002-1557",
               "CVE-2002-1558", "CVE-2004-0306", "CVE-2004-0307", "CVE-2004-0308");
 script_bugtraq_id(9699, 6084, 6083, 6082, 6081, 6078, 6076, 6073, 5058);
 script_xref(name:"OSVDB", value:"4008");
 script_xref(name:"OSVDB", value:"4009");
 script_xref(name:"OSVDB", value:"4010");
 script_xref(name:"OSVDB", value:"5045");
 script_xref(name:"OSVDB", value:"8879");
 script_xref(name:"OSVDB", value:"8924");
 script_xref(name:"OSVDB", value:"8925");
 script_xref(name:"OSVDB", value:"8926");
 script_xref(name:"OSVDB", value:"8927");
 script_xref(name:"OSVDB", value:"8939");

 script_name(english:"Cisco ONS Multiple Remote Vulnerabilities (20040219-ONS)");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote Cisco device has multiple vulnerabilites."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, the remote Cisco ONS platform has\n",
     "the following vulnerabilities :\n\n",
     "  - The TFTP server allows unauthenticated access to TFTP\n",
     "    GET and PUT commands. An attacker may exploit this flaw\n",
     "    to upload or retrieve the system files of the remote\n",
     "    ONS platform.\n\n",
     "  - A denial of service attack may occur through the network\n",
     "    management port of the remote device (1080/tcp).\n\n",
     "  - Superuser accounts cannot be disabled over telnet."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/707/cisco-sa-20040219-ONS.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the fixes referenced in Cisco's advisory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/sysDesc");

 exit(0);
}

port = 0;

sysDesc = get_kb_item("SNMP/sysDesc"); 
if ( ! sysDesc ) exit(0);

if ("Cisco ONS" >!< sysDesc ) exit(0);

if ( egrep(pattern:"Cisco ONS 15327.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15327.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 2) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15454.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15454.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 5 ) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15600.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15600.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 1 ) security_hole(port);
}
