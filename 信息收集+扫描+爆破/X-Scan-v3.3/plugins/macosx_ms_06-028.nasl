#TRUSTED 35b49fe3fdb358125247c0dbf6eab0cc18542f2a2102595050b952f170d3770c30fe6f096783cf00fc5ac5348b6cecade8c28cb65fe90c55553cc26dcf8367aedcffbdddbcc34214f4127f4dc557c6a0c2ce9c0e1e29f248ee23bc1da69db2e096b970e1cd8ead17efeb533d1fd58e32d81770923411d9851c7c8bc5f40cc9dc50c3b49e25bbc4eb6270eebb9e6f13ca156e13c09293cdb9c6ace4f255fd28c9da2cf8efd34e9f991fe1170ee879943048a365b4802a8a5e206ffb62dfd87f139897871afb5edbe31e837f3e31e2fb78b05cb75238006023b1eedb6baf312c9c9d4bc9b04c64d64ad0ca80354f3383e9caa4bbd4679525db9e673eaa49d07a4c26e787e8e12d1f146c50b6313adf796ac8236696e22f32d8bf8634e3a300cbc7f425f7345f7465b79a8415b974cdcd87adfa988d6148d7fc40021d1591620dd8f53fdb2149b4a21150c7c6ee47bea87c4b700a3d7175a95dd3660806b9363ee57798873c7d87c21e099c753d3ff82f660b0a331dcde8332331149e3ef729a8b84690c7628f16e6b4976d4b6fb8f264456e57a6586d8846bec6b7c2e96239f0c14fedd8e08c30726dff0d70fa855233bd1bb3b3a16a98631c0a7ade4af411281bf85c61b8de963ae565f3df8c5c78c838c6881cf45915ed3cd162470609191f033a363492a82779299d2622727e65a90473b470d04149074afb9d3771ecdb5b64
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(21724);
 script_version ("1.8");

 script_cve_id("CVE-2006-0022");
 script_bugtraq_id (18382);
 script_xref(name:"OSVDB", value:"26435");

 script_name(english:"MS06-028: Vulnerability in Microsoft PowerPoint Could Allow Remote Code Execution (916768) (Mac OS X)");
 script_summary(english:"Check for PowerPoint 2004 and X");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Microsoft\n",
   "PowerPoint."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Microsoft PowerPoint that may\n",
   "allow arbitrary code to be run.\n",
   "\n",
   "To succeed, the attacker would have to send a rogue file to a user of\n",
   "the remote computer and have it open it with PowerPoint.  A\n",
   "vulnerability in the font parsing handler would then result in code\n",
   "execution."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for PowerPoint X and 2004 for\n",
   "Mac OS X :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms06-028.mspx"
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office X");

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
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_hole(0);
	  else
          # < 11.2.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 4 ) ) ) security_hole(0);
	} 
}
