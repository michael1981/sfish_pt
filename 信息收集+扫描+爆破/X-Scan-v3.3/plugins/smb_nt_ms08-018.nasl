#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31791);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-1088");
 script_bugtraq_id(28607);
 script_xref(name:"OSVDB", value:"44212");

 name["english"] = "MS08-018: Vulnerability in Microsoft Project Could Allow Remote Code Execution (950183)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft Project." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Project which has a 
vulnerability in the way it validates memory which could be used by 
an attacker to execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to spend a 
specially crafted Project document to a user on the remote host and 
lure him into opening it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Project 2000, 2002 
and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS08-018.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 950183";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Project/Version");
 exit(0);
}

include("smb_func.inc");


str = vers = get_kb_item("SMB/Office/Project/Version");
if ( isnull(vers) ) exit(0);
vers = split(vers, sep:'.', keep:FALSE);
for ( i = 0 ; i < max_index(vers) ; i ++ ) vers[i] = int(vers[i]);

vers9  = make_list(9, 0,2008, 228);
vers10 = make_list(10,0,2108,1228);
vers11 = make_list(11,3,2007,1529); # SP3

if ( vers[0] == 9 ) ref = vers9;
else if ( vers[0] == 10 ) ref = vers10;
else if ( vers[0] == 11 ) ref = vers11;
else exit(0);

for ( i = 0 ; i < max_index(vers) ; i ++ )
{
  if ( vers[i] < ref[i] ) 
	{
	 {
 set_kb_item(name:"SMB/Missing/MS08-018", value:TRUE);
 security_hole(port:kb_smb_transport(), extra:'\nWinProj.exe version ' + str + ' is installed on the remote host\n');
 }
	exit(0);
	}
  else if ( vers[i] > ref[i] ) break;
}
