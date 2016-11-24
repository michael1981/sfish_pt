#TRUSTED 0c5298437336e4d742298db26c4ba2926aef4a632b3576be9fd303ec5f567c14d127b633753fe14602b6b3019919b0d37fc4c28039d156ea2c284e2e1078e0681ca2951a7ca253f88fa6309f64c9c8cfcb3efe2dd8404450741ea858e6ee9287d06ab23a58c82646bc5c657b21835009e9af0dbb3a6fe778b16f87ca7465150bf34e67bd33d94929fa0346f82c58e54d4cec26ca11588aa3dc3c97e8d6c61fabe7321019bc8194b23bc4db9499137d1dc71ad11ab581cace7fe67f6ddc657cea93d78c2c78f7ecf2ec4cca29436f1f580bb2a56e80920dff6df77094ef1c70d25c3123412cfd290b04023d785bbe32e9eebc2316f1bb2ee873ca831d1befde51c1bc32082bd755674f8f4e11e780448c6cb9aa1572d48ad80c9a0f3a491dfc3a38ecef208c90b40e36821aaa2ab2998e75cab302f366995fe62995105f16a719359f9a2f463709cff5a0ea13c608211fccf8cdf43b347ed65adaeaa6e482363615c0ef684b4ea9e45ce6415fa3e5a47908a8c8423a8491b9e72675f2d49831eb095bbf053c46045ba79f9a7c9e22b7bacbbd0d1aeec8e1b00afebc79ff984c6083c6b630bc16d662d5e92103e6f112903dd28ee1b7aa69862a90e371ac476e9aab3130aab2ec2c08ef1fdb8d8a13408804aab651b520327f95fbbfb807ab83884e951c0b51049896f6ffd5fc824aa30128549be9f2dc5581b70dc0b10aa26a61
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(34290);
 script_version("1.4");

 script_cve_id(
  "CVE-2008-1185",
  "CVE-2008-1186",
  "CVE-2008-1187",
  "CVE-2008-1188",
  "CVE-2008-1189",
  "CVE-2008-1190",
  "CVE-2008-1191",
  "CVE-2008-1192",
  "CVE-2008-1193",
  "CVE-2008-1194",
  "CVE-2008-1195",
  "CVE-2008-1196",
  "CVE-2008-3103",
  "CVE-2008-3104",
  "CVE-2008-3105",
  "CVE-2008-3106",
  "CVE-2008-3107",
  "CVE-2008-3108",
  "CVE-2008-3109",
  "CVE-2008-3110",
  "CVE-2008-3111",
  "CVE-2008-3112",
  "CVE-2008-3113",
  "CVE-2008-3114",
  "CVE-2008-3115",
  "CVE-2008-3637",
  "CVE-2008-3638"
 );
 script_bugtraq_id(28125, 30144, 30146, 31379, 31380);
 if (NASL_LEVEL >= 3000)
 {
  script_xref(name:"OSVDB", value:"46955");
  script_xref(name:"OSVDB", value:"46956");
  script_xref(name:"OSVDB", value:"46957");
  script_xref(name:"OSVDB", value:"46958");
  script_xref(name:"OSVDB", value:"46959");
  script_xref(name:"OSVDB", value:"46960");
  script_xref(name:"OSVDB", value:"46961");
  script_xref(name:"OSVDB", value:"46962");
  script_xref(name:"OSVDB", value:"46963");
  script_xref(name:"OSVDB", value:"46964");
  script_xref(name:"OSVDB", value:"46965");
  script_xref(name:"OSVDB", value:"46966");
  script_xref(name:"OSVDB", value:"46967");
  script_xref(name:"OSVDB", value:"49091");
  script_xref(name:"OSVDB", value:"49092");
 }

 name["english"] = "Mac OS X : Java for Mac OS X 10.5 Update 2";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.5 host is running a version of Java for Mac OS
X that is missing update 2. 

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to execute
arbitrary code on the remote host. 

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3179" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00007.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.5 update 2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Check for Java Update 2 on Mac OS X 10.5";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");

function exec(cmd)
{
 local_var ret, buf;

 if ( islocalhost() )
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
 else
 {
  ret = ssh_open_connection();
  if ( ! ret ) exit(0);
  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
 }

 if ( buf !~ "^[0-9]" ) exit(0);

 buf = chomp(buf);
 return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# Mac OS X 10.5 only
if ( egrep(pattern:"Darwin.* 9\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 12.2.0
 if ( int(array[0]) < 12 ||
     (int(array[0]) == 12 && int(array[1]) < 2 ) )
 {
   security_hole(0);
 }
}
