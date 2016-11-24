#
# (C) Tenable Network Security, Inc.
#

#http://supportconnect.ca.com/sc/solcenter/sol_detail.jsp?docid=1&product=ETRID&release=3.0.5&number=10&type=&os=NT&aparno=QO66178&searchID=361777&pos=NT 


include("compat.inc");

if(description)
{
 script_id(18537);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2005-0968");
 script_bugtraq_id(13017);
 script_xref(name:"OSVDB", value:"15273");

 script_name(english:"CA eTrust Intrusion Detection CPImportKey Function Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote IDS service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CA eTrust Intrusion Detection System, a
security solution with intrusion detection, antivirus, web filtering
and session monitoring. 

The remote version of this software is affected by a denial of service
vulnerability in the way it uses 'CPImportKey' function.  An attacker
can exploit this issue to crash the remote service by sending a
specially-crafted administration packet." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=223&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/395012" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86be784a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.5.57 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Determines if eTrust Intrusion Detection System is vulnerable to a Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("etrust_ids.nasl");
 script_require_keys("eTrust/intrusion_detection_system");
 exit(0);
}

vers = get_kb_item ("eTrust/intrusion_detection_system");
if (!vers) exit(0);

vers = split (vers, sep:".", keep:0);

if ( ( (vers[0] == 3 ) && (vers[1] == 0) && (vers[2] < 557) ) )
  security_warning(get_kb_item("Services/eTrust-IDS"));
