#
# (C) KK Liu
#

# Changes by Tenable:
#  - Fixed the request
#  - Shorter description
#  - Fixed the version number check 
#  - Added a check on port 10202, 10203
#  - Added additional OSVDB ref (1/15/2009)
#  - Changed plugin family (8/14/2009)


include("compat.inc");

if(description)
{
 script_id(17307);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2005-0581", "CVE-2005-0582", "CVE-2005-0583");
 script_bugtraq_id(12705);
 script_xref(name:"IAVA", value:"2005-t-0007");
 script_xref(name:"OSVDB", value:"14320");
 script_xref(name:"OSVDB", value:"14321");
 script_xref(name:"OSVDB", value:"14323");
 script_xref(name:"OSVDB", value:"14389");

 script_name(english:"CA License Service Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Computer Associate License Application. 

The remote version of this software is vulnerable to several flaws
which may allow a remote attacker to execute arbitrary code on the
remote host with the SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20050302.html" );
 script_set_attribute(attribute:"solution", value:
"http://supportconnectw.ca.com/public/ca_common_docs/security_notice.asp" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"CA License Service Stack Overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 KK Liu");
 script_family(english: "Windows");
 script_require_ports(10202, 10203, 10204);
 exit(0);
}

include("global_settings.inc");
include('misc_func.inc');

req = 'A0 GETCONFIG SELF 0 <EOM>\r\n';
ports = make_list(10202, 10203, 10204);
foreach port ( ports )
{
 if ( get_port_state(port) ) 
  {
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:620);
	close(soc);
	if ( strlen(r) > 0 )
	{
     	chkstr = strstr(r, "VERSION<");
	if (chkstr ) 
 	{
	 register_service(port:port, proto:"CA_License_Service");
         if (egrep (pattern:"VERSION<[0-9] 1\.(5[3-9].*|60.*|61(\.[0-8])?)>", string:chkstr)) 
	 {
          security_hole(port);
	 }
	}
       } 
    }
  }
}
