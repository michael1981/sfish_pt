#TRUSTED 7e299bf040eb1fe445ba9a608daaef81a636744b7c49affef8a8f48e91c49daba34a1c6035032ad58c034fe76c68c8947e9ca44f946c55f52bfabdd23eeb643d98f347b38a4e7bb8ad2189dcd0ad7f7863644021b00550405a20e4ea0dd3630e701bf71445684111fe312ce9aabec19baa71088c171cde72f286f841c820341a73d56843ce2c342fbfe921d1de8a5bdd269a48f8a6471064c4ef91b886e64d2807019b4b8794c4f2ca8a575005a6c2aaa9dcfad3d05d54d5851c48d5ef721dd52c84ce5931c9c059155e248ec23cc2e7e23136f3e4f765c006c7a051e0cd3583db3efa418457d31275738d82e27be6ebd1777b4613779fa59c1ada04f51efeecddb3d015c108dfb1789f97440f0184cf81f8b247b1e91cf9f57085a0d530059e658e3691c51219e136ce8d8c7da7eba3f1a6091dfbfd5b9be6a2d9d78fff0f042117150e6987f4c4212b41dbc69e24131418edf5539ff04f21fb35ca90f82b079dbdc174b66dc1f5671d12afef27b622541f922644346762685336aeb13ed790ad9952f37404ed065069eed416916951f054afbdee096858887da1447532c1d051dd365b366fa732f1d06aa754ef532594b085d748d14368a9ca41ee886dacabb6802c15ec5a8f1884e25c18bcf22095fb60ca9f712007d554372ee0ed43af75fd0d555d56947bd1dcce67f1a8a3d79c3a4a2def07784c0bcac4ea7386705f4d
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);
if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if(description)
{
 script_id(25173);
 script_version("1.8");

 script_cve_id(
  "CVE-2007-0035", 
  "CVE-2007-0215", 
  # "CVE-2007-0870",    Microsoft Office 2004 for Mac not impacted
  "CVE-2007-1202", 
  "CVE-2007-1203", 
  "CVE-2007-1214", 
  "CVE-2007-1747"
 );
 script_bugtraq_id(23760, 23779, 23780, 23804, 23826, 23836);
 script_xref(name:"OSVDB", value:"34387");
 script_xref(name:"OSVDB", value:"34388");
 script_xref(name:"OSVDB", value:"34393");
 script_xref(name:"OSVDB", value:"34394");
 script_xref(name:"OSVDB", value:"34395");
 script_xref(name:"OSVDB", value:"34396");
 
 script_name(english:"MS07-023 / MS07-024 / MS07-025: Vulnerabilities in Microsoft Office Allow Remote Code Execution (934233 / 934232 / 934873) (Mac OS X)");
 script_summary(english:"Check for Office 2004 and X");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Microsoft\n",
   "Office."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Microsoft Office that is\n",
   "affected by various flaws that may allow arbitrary code to be run. \n",
   "\n",
   "To succeed, the attacker would have to send a rogue file to a user of\n",
   "the remote computer and have him open it with Microsoft Word, Excel or\n",
   "another Office application."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Office for Mac OS X :\n",
   "\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS07-023.mspx\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS07-024.mspx\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS07-025.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");

  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   ssh_close_connection();
  }
  else
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", off2004));


 if ( buf =~ "^11\." )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
	  if ( (int(vers[0]) == 11 && int(vers[1]) < 3)  || 
               (int(vers[0]) == 11 && int(vers[1]) == 3 && int(vers[2]) < 5 ) ) security_hole(0);
	} 
}
