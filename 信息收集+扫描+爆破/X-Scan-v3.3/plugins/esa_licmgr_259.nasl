#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25080);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-2059");
  script_bugtraq_id(23454);
  script_xref(name:"OSVDB", value:"34920");
  script_xref(name:"Secunia", value:"24881");

  script_name(english:"eIQnetworks Enterprise Security Analyzer License Manager < 2.5.9 Multiple Remote Overflows");
  script_summary(english:"Checks for buffer overflows in ESA < 2.5.9");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of eIQnetworks Enterprise Security Analyzer installed on
the remote host contains multiple buffer overflows in its License
Manager service.  Using long arguments to various commands, an
unauthenticated remote attacker may be able to leverage this issue to
crash the affected service or possibly execute arbitrary code on the
affected host with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.infigo.hr/en/in_focus/advisories/INFIGO-2007-04-05" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/465488/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.eiqnetworks.com/support/eIQ_Security_Advisory_04_13_07.pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Enterprise Security Analyzer version 2.5.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("esa_licmgr_detect.nasl");
  script_require_ports("Services/esa_licmgr", 10616);

  exit(0);
}


port = get_kb_item("Services/esa_licmgr");
if (!port) port = 10616;
if (!get_port_state(port)) exit(0);


build = get_kb_item("ESA/Licmgr/"+port+"/Version");
if ( ! build ) exit(0);
# Look at the product and build number.
pat = "^([^ ]+) +v([0-9][^ ]+) +([^ ]+)";
m = eregmatch(pattern:pat, string:build);
if ( ! m ) exit(0);
prod = m[1];
ver = m[2];
vuln = 0;
if (prod != "ESA") exit(0);
v = split(ver, sep:'.', keep:FALSE);
if ( int(v[0]) < 2 ||
      ( int(v[0]) == 2 && ( int(v[1]) < 5 || (int(v[1]) == 5 && int(v[2]) < 9))) ) 
{
 report = string(
          "Nessus has used the build version, ", ver, ", of the software on the\n",
          "remote host to determine that it is vulnerable to these issues.\n"
        );
        security_hole(port:port, extra:report);
}
