#TRUSTED 86c0ab6002be3bda95e20e3bf84f89ef5e4bf976b413548f7bdfb15d1d203b0eac51fd4130d9bf42e124383e29d70462dc5ddb70d35bde98083f2fc2d17840d421706aacd13843e93bca63940937cfca1cf858a82b4f06857d1184c0d7bdadbd13758186408349f3c45f14daacfcdafbba71d78c10eed3158e9e6e0754ab07290abde373526e389bd401744643d64e1d5fb309eaa5c7bc0dd6d5e40dc91ad4b769566674b71a5774b820958924ce7885a2f2e88dd8500f23116474476e71e1f2a367fd89f7686d93f4424d98e61b70fd9cff70d5ab9d6d66934ce70677828084e73e1a869d7c0a873a7f7a3bec4acb91c6bd6576a2735dd7a1ce013654fec7ff62f0525cabd6ce2c4c95970b05f1f536ae0045efeebbcdee81936761db09f96ee6e5ac876e603f2f4fa5e5cdf997e2bd55ad308595a5e3047b9318bc6e201780c3d653427781553bf5c09b78fda1c8f27c2552b21ee018d4168118f91e2c24bd66eb682e3db29fa8fa3494cb4870ee9330e49aab4d3eeaa4b36df446547ab321e437187067071c70a38d401438814dcfc892144080a75ac20f0eb89b7d6bb39872f0568751751c8226cf84cf2cf0e467b44fa274396aa82924d895b7e24091e463ce5a7803f6647ccdbdd9ef4fdc5222d09d9792776991694834bf891045069fb5fdc609e08fd5ddc3704d730248842f6c6db55e3ce5b8d7166892be6aaf10bc
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(22539);
 script_version("1.5");

 script_cve_id(
  # "CVE-2006-3435", 
  "CVE-2006-3876", 
  "CVE-2006-3877", 
  "CVE-2006-4694", 
  "CVE-2006-2387", 
  "CVE-2006-3431",
  "CVE-2006-3867",
  "CVE-2006-3875",
  "CVE-2006-3647",
  # "CVE-2006-3651",
  # "CVE-2006-4534",
  "CVE-2006-4693",
  "CVE-2006-3434",
  "CVE-2006-3650",
  "CVE-2006-3864"
  # "CVE-2006-3868"
 );
 script_bugtraq_id(
  18872, 
  20226, 
  20322, 
  20325, 
  20341, 
  20344, 
  20345, 
  20382, 
  20383, 
  20384, 
  20391
 );
 script_xref(name:"OSVDB", value:"27053");
 script_xref(name:"OSVDB", value:"28539");
 script_xref(name:"OSVDB", value:"29259");
 script_xref(name:"OSVDB", value:"29427");
 script_xref(name:"OSVDB", value:"29428");
 script_xref(name:"OSVDB", value:"29429");
 script_xref(name:"OSVDB", value:"29440");
 script_xref(name:"OSVDB", value:"29442");
 script_xref(name:"OSVDB", value:"29443");
 script_xref(name:"OSVDB", value:"29444");
 script_xref(name:"OSVDB", value:"29445");
 script_xref(name:"OSVDB", value:"29447");
 script_xref(name:"OSVDB", value:"29448");

 script_name(english:"MS06-058 / MS06-059 / MS06-0060 / MS06-062: Vulnerabilities in Microsoft Office Allow Remote Code Execution (924163 / 924164 / 924554 / 922581) (Mac OS X)");
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
   "affected by various flaws that may allow arbitrary code to be run.\n",
   "\n",
   "To succeed, the attacker would have to send a rogue file to a user of\n",
   "the remote computer and have it open it with Microsoft Word, Excel,\n",
   "PowerPoint or another Office application."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Office for Mac OS X :\n",
   "\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS06-058.mspx\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS06-059.mspx\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS06-060.mspx\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS06-062.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
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
  offX    = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office X/Office");

  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   if ( buf !~ "^11" ) buf = ssh_cmd(cmd:offX);
   ssh_close_connection();
  }
  else
  {
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", off2004));
  if ( buf !~ "^11" )
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", offX));
  }


 if ( buf =~ "^(10\.|11\.)" )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
	  # < 10.1.8
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 8 ) ) )  security_hole(0);
	  else
          # < 11.3.0
	  if ( int(vers[0]) == 11 && int(vers[1]) < 3  ) security_hole(0);
	} 
}
