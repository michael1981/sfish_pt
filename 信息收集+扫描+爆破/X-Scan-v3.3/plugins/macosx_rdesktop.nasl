#TRUSTED 7f767675ccd46331f13c940c20ce02c07d81d08e1faed01a1dcc6af5f238a4f3345a446a459c9e9c64580eba22c0b1db789bc76aeaca827526bb0f2deb6239a40050b8a1ff3235da8a91bc2bbac84db8e1a1980b47f3da4a80c6d525df3836e7bff4072ae675e586996947da10522aef891f12b6a896cf06d9129348b3f00a3a35eabc0bb776e12ea9feb04ceef81b2caa81bf64d503adbd048a8f2cd459df7c0b6905276029f071cafc708f130e0b546768af75b2b508ca9083d0b4b673230b7d5e748afda031678b07e2fbfed98bf1699779fb02d9a71bc370fe54a655449a8af3b0510b393d39f688c52e0e846f0065bd7db98c3276df6df1c6745896a461d2b1bb4d0e4f1e45a02b719c5233826431e275f7ae8623eb195ab8a65da2327efd0738131cd4dd980c59469d4cc822adb4836a213b34c21a2183ce7d8eb0599b535e9d4c313f15ffb000d033b1b28aae20564ab80e3aa808b9cfd50b32485622e0c58c2c1b9ad6806ca27ebdb8b7ef8073d6c5b8a39a33ef0b0b949e87b48b56feb1187cddb1b41984e9336f36d9003d2ebf942037163aee89fc9cdd26749d1bdc3ecd07965f0383446328db0f68562f2ac43cdae76affbc1bb989c1bea2b79887ec53a5c18c3f1b65a1aec4c6c93953a6254c9b9ab0f400ac3b5f8d34f620e3b6821bb8ca8cfbc44c077f2c970a4b55ad4250b06a114f403debe9b674f7346b
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");


if(description)
{
 script_id(40563);
 script_version("1.2");

 script_cve_id("CVE-2009-1133", "CVE-2009-1929");
 script_bugtraq_id(35971, 35973);
 script_xref(name:"OSVDB", value:"56911");
 script_xref(name:"OSVDB", value:"56912");

 script_name(english:"MS09-044: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (Mac OS X)");
 script_summary(english:"Check for Remote Desktop Connection for Mac OS X");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Microsoft\n",
   "Remote Desktop Connection."
  )
 );
 script_set_attribute(
  attribute:"description",
  value:string(
   "The remote host contains a version of the Remote Desktop client that\n",
   "contains several vulnerabilities that may allow an attacker to\n",
   "execute arbirtary code on the remote host. \n",
   "\n",
   "To exploit these vulnerabilities, an attacker would need to trick a\n",
   "user of the remote host into connecting to a rogue RDP server."
  )
 );
 script_set_attribute(
  attribute:"solution",
  value:string(
   "Microsoft has released a patch for Remote Desktop Client for\n",
   "Mac OS X :\n",
   "\n",
   "http://www.microsoft.com/technet/security/Bulletin/MS09-044.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
 );
 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2009/08/11"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2009/08/11"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  file    = GetBundleVersionCmd(file:"Remote Desktop Connection.app", path:"/Applications");
  file    = ereg_replace(pattern:"version\.plist", replace:"Info.plist", string:file);
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:file);
   ssh_close_connection();
  }
  else
  {
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", file));
  }

 if ( buf =~ "^2" )
 {
  v = split(buf, sep:'.', keep:FALSE);
  if ( int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) == 0 )
	security_hole(port:0);
 }
}
