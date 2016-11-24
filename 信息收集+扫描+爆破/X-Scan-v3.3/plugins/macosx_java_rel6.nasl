#TRUSTED a6e0c74e748238c2610369b46c3e47b460c90555d7379cdcc6b9f4a1054d1b393698bd55468389ec9383f16e12a32b3a8a7b0e7e6e24a6eb2d1ac3e2f60cfd8f8dc5d414fa4d2835ddbc017edc626c6ce73aa378fec57736649fa84ee3f690b8c345a7bfa1fd6dae3bd2f28b90c14637466737079e9648d98d4dc15794bbb42b01706cbd5ce6b66054e60b662fbfcf30b75bad1fac2f9a26abc3819b57e1e0d189c90bd2c2c43d89188532d6e901c20ea792a595dbe6d90fb29653b43b014a9695d0d52f1b5fe8df25689e9c0e1fd685f2cf03455b33bad16ba5b8ea9d421d29975ce9e55f80a8cba9d6cb54d81f9cd841db3ac50d85483d6f08be152f0382393c5f388b8ad3e2f0be740c2a7beafe37bb9a85951e188a4def247aedec535a8ebc633ba814fc1f05cdf50d67ec9e39def2bd6f58a3525fd46563fd31661a8b7db225398d121fed5e9eb15aaf88c7593edafa3aecdbc3e018fd7691a4445fe0224f8657d52959d3f67c4164c8f4830edcf293f2c41c98eb41630f694d820d725d11b98fbcba89d51769b1f111a84f7a17acdbd7bb5b62c990efec436341931787ccd16c60826e825b8bc5705280499f88aabfeac93ad5aaf7fa8580bb35e02c29565807c3499de4800ec8c9dd09fb614d29a4a7ae0455e18001b68349491d242758fd683617fcb79d78a149ccf11b9f356c18efe4ef1edecc7240a33a866fe790
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if ( NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if(description)
{
 script_id(29702);
 script_version("1.6");

 script_cve_id(
  "CVE-2006-4339",
  "CVE-2006-6731",
  "CVE-2006-6736",
  "CVE-2006-6745",
  "CVE-2007-0243",
  "CVE-2007-2435",
  "CVE-2007-2788",
  "CVE-2007-2789",
  "CVE-2007-3503",
  "CVE-2007-3504",
  "CVE-2007-3655",
  "CVE-2007-3698",
  "CVE-2007-3922",
  "CVE-2007-4381",
  "CVE-2007-5232",
  "CVE-2007-5862"
 );
 script_bugtraq_id(
  21673,
  21674,
  21675,
  22085,
  24690,
  24695,
  24832,
  24846,
  25054,
  25340,
  25918,
  26877
 );
 script_xref(name:"OSVDB", value:"28549");
 script_xref(name:"OSVDB", value:"32357");
 script_xref(name:"OSVDB", value:"32358");
 script_xref(name:"OSVDB", value:"32394");
 script_xref(name:"OSVDB", value:"32834");
 script_xref(name:"OSVDB", value:"32931");
 script_xref(name:"OSVDB", value:"32932");
 script_xref(name:"OSVDB", value:"32933");
 script_xref(name:"OSVDB", value:"32934");
 script_xref(name:"OSVDB", value:"35483");
 script_xref(name:"OSVDB", value:"36199");
 script_xref(name:"OSVDB", value:"36200");
 script_xref(name:"OSVDB", value:"36201");
 script_xref(name:"OSVDB", value:"36202");
 script_xref(name:"OSVDB", value:"36488");
 script_xref(name:"OSVDB", value:"36662");
 script_xref(name:"OSVDB", value:"36663");
 script_xref(name:"OSVDB", value:"37755");
 script_xref(name:"OSVDB", value:"37756");
 script_xref(name:"OSVDB", value:"37765");
 script_xref(name:"OSVDB", value:"37766");
 script_xref(name:"OSVDB", value:"40740");

 name["english"] = "Mac OS X : Java for Mac OS X 10.4 Release 6";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X that is older than release 6. 

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to escalate its
privileges and to add or remove arbitrary items from the user's
KeyChain. 

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307177" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.4 release 6." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Check for Java Release 6";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
# Mac OS X 10.4.10, 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.(10|11)\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) <= 7 ) )
 {
  cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"SourceVersion");
  buf = exec(cmd:cmd);
  if ( strlen(buf) && int(buf) < 1120000 ) security_hole(0);
 }
}
