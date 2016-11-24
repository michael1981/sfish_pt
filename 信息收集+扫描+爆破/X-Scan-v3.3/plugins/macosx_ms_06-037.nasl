#TRUSTED 2db79a7b6a073af693dc418dc6b536df7187ad6265a55a5ad9d909092c9e0ab5d65a722aee82ff10bc49a24167408b97db32f772aa2955bd745aacafa5e056e548de280c21954405742e7a4c2947e9082edc5616b1c805682b32c0d8ce1f47be86be1cb70973d8fd82dd2cbd4dc12b20239fbe4c54854e3a4d045ab0b78a73c199c701eb0b6c85413b2d728813a4afd70d406cb69d6cb1d68835daeef09451e15a09922e101f16da00288fa553d27f40feed1c6b8c2a959b246b46086fc6dc051e7d2262492da6a6551a8c83c3c2c8be47eb76440b5646331dddbc3025f59c58d2a73e51d36b53878dc7364f2ddc2c47a603114dc4fd4ea41770187f0f974b5bb366a1f3a8bb711f3521dec6c23be6804d2a2ed26bc53bd63bc93dd24b92c9c1ca071a7d9e87547cec807c056791cd58253d48b28d0c57eef2178304d8d977a5a61eab7b18fcab2432afa7f2d3f7a4273d80ec9f22d30d1a857a789ee010acd923675cfb3a099fa9e8462762bb1d3b8aeec8a76fab460f8ccb10a8bfe07e31c8e175dde3273e1a73efd145e8e3e968a86c5a2411467635929d978983e924761fd3e97a31244eb9461673303eaddf3fd537a468d1efd6320d2f464012decc83009a40fef56cfa7a0fa44484703426984a0e345df2f8b35b02d2ca5dfc56c4a9c8f3df449898b66a78cec962f72d81307923f5e4248505a782b0780d959300b905
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3004) exit(1);
if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if(description)
{
 script_id(22025);
 script_version("1.9");

 script_cve_id(
  "CVE-2006-1301", 
  "CVE-2006-1302", 
  "CVE-2006-1304", 
  "CVE-2006-1306", 
  "CVE-2006-1308", 
  "CVE-2006-1309", 
  "CVE-2006-2388", 
  "CVE-2006-3059", 
  "CVE-2006-1316", 
  "CVE-2006-1318", 
  "CVE-2006-1540", 
  "CVE-2006-2389"
 );
 script_bugtraq_id(
  18422,
  18853,
  18885,
  18886, 
  18888, 
  18889, 
  18890, 
  18910, 
  18911, 
  18912, 
  18938
 );
 script_xref(name:"OSVDB", value:"26527");
 script_xref(name:"OSVDB", value:"27148");
 script_xref(name:"OSVDB", value:"27149");
 script_xref(name:"OSVDB", value:"27150");
 script_xref(name:"OSVDB", value:"28532");
 script_xref(name:"OSVDB", value:"28533");
 script_xref(name:"OSVDB", value:"28534");
 script_xref(name:"OSVDB", value:"28535");
 script_xref(name:"OSVDB", value:"28536");
 script_xref(name:"OSVDB", value:"28537");
 script_xref(name:"OSVDB", value:"28538");
 
 script_name(english:"MS06-037 / MS06-038: Vulnerabilities in Microsoft Excel and Office Could Allow Remote Code Execution (917284 / 917285) (Mac OS X)");
 script_summary(english:"Check for Excel 2004 and X");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Microsoft\n",
   "Excel."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Microsoft Office that is\n",
   "affected by various flaws that may allow arbitrary code to be run.\n",
   "\n",
   "To succeed, the attacker would have to send a rogue file to a user of\n",
   "the remote computer and have it open it with Microsoft Excel or\n",
   "another Office application."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Office for Mac OS X :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms06-037.mspx\n",
   "http://www.microsoft.com/technet/security/bulletin/ms06-038.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P"
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office X");
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   if ( buf !~ "^11" )
   buf = ssh_cmd(cmd:offX);
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
	  # < 10.1.7
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_warning(0);
	  else
          # < 11.2.5
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 5 ) ) ) security_warning(0);
	} 
}
