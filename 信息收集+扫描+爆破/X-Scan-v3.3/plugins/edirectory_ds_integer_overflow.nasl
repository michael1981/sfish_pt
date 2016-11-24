#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33397);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-1809", "CVE-2008-3159");
  script_bugtraq_id(30085, 30175);
  script_xref(name:"OSVDB", value:"46708");
  script_xref(name:"OSVDB", value:"46928");

  script_name(english:"Novell eDirectory < 8.8.2 FTF2 / 8.7.3 SP10b Multiple Remote Overflows");
  script_summary(english:"Checks version from an ldap search");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote directory service is affected by multiple buffer overflows." );
 script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell. 

The installed version of eDirectory is affected by an integer overflow
issue in ds.dlm / dhost.exe (bound by default to TCP port 524) as well
as a heap buffer overflow that can be triggered by passing NULL search
parameters to the LDAP service.  An unauthenticated attacker may be
able to leverage either issue to execute code on the remote host with
SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-041/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-07/0144.html" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=724" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-07/0145.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3694858" );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3843876" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to eDirectory 8.8.2 FTF2 / 8.7.3 SP10b or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ldap_search.nasl");
  script_require_keys("Services/ldap");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ldap");
if (isnull(port)) exit(0);

banner = get_kb_item(string("LDAP/",port,"/vendorVersion"));
if ( "Novell eDirectory" >!< banner ) exit(0);

if (!egrep(pattern:"^LDAP Agent for Novell eDirectory [0-9]+\.[0-9]+.* \([0-9]+\.[0-9]+\)$", string:banner))
  exit(0);

main = ereg_replace(pattern:"^LDAP Agent for Novell eDirectory ([0-9]+\.[0-9]+).* \([0-9]+\.[0-9]+\)$", string:banner, replace:"\1");
version = ereg_replace(pattern:"^LDAP Agent for Novell eDirectory [0-9]+\.[0-9]+.* \(([0-9]+\.[0-9]+)\)$", string:banner, replace:"\1");

version = split(version, sep:".", keep:FALSE);
build = int(version[0]);
rev = int(version[1]);

if ( ( ("8.7" >< main) && ( (build < 10555) || ( build == 10555 && rev < 98 ) ) ) ||
     ( ("8.8" >< main) && ( (build < 20216) || ( build == 20216 && rev < 51 ) ) ) )
{
 if(report_verbosity > 0)
 {
  report = string(
          "\n", banner," is installed on the remote host.\n"
        );
  security_hole(port:port, extra:report);
 }	
 else	
   security_hole(port); 
}
