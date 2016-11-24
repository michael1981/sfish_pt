#
# (C) Tenable Network Security, Inc.
#

#These vulnerabilities are documented as the following Cisco bug IDs
#    * CSCed06531 (IP)
#    * CSCed86946 (ICMP)
#    * CSCec88426/CSCec88508/CSCed85088/CSCeb07263/CSCec21429 (TCP)
#    * CSCec59739/CSCed02439/CSCed22547 (Last-ACK)
#    * CSCec88402/CSCed31918/CSCed83309/CSCec85982/CSCec21435/CSCee03697 (UDP)
#    * CSCea16455/CSCea37089/CSCea37185 (SNMP)
#    * CSCee27329 (passwd)


include("compat.inc");

if(description)
{
 script_id(16201);
 script_cve_id("CVE-2004-1432", "CVE-2004-1433", "CVE-2004-1434", "CVE-2004-1435", "CVE-2004-1436");
 script_bugtraq_id(10768);
 script_xref(name:"OSVDB", value:"8149");
 script_xref(name:"OSVDB", value:"8150");
 script_xref(name:"OSVDB", value:"8151");
 script_xref(name:"OSVDB", value:"8152");
 script_xref(name:"OSVDB", value:"8153");
 script_xref(name:"OSVDB", value:"8154");
 script_xref(name:"OSVDB", value:"8155");
 script_version("$Revision: 1.11 $");

 script_name(english:"Cisco ONS Multiple Remote Vulnerabilities (20040721-ons)");

 script_set_attribute(attribute:"synopsis", value:
"The remote network device is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Cisco ONS platform contains various vulnerabilities that
may allow a remote attacker to cause a denial of service in the remote
control cards or to bypass authentication on the remote device." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/cisco-sa-20040721-ons.shtml" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate update as referenced in the vendor advisory
above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2005-2009 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

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
 if ( int(int_version[1]) <= 3 ) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 3) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 6 && int(int_version[3]) <= 1) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15454.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15454.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 3 ) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 3) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 5 ) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 6 && int(int_version[3]) <= 1) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15600.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15600.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 1 ) security_hole(port);
}
