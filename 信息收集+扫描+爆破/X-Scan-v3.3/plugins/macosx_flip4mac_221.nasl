#TRUSTED 73e4665a19b09fdafef34a80481b48aeea4bb401d9d20c12d206e913f501499c1b644911fe59146b8cd5d6781b080cbc36069519cccc26be886099f299dca46749804baa58a2f2420f1b43a73474a47519edc6bfa035147a23fbaf592e30c8be093caff8ecb6600cfea43c7dd9c7d49354d5467b2e948b80bb50375b92f29ea0b9fe480c4cf3e16f944ecf08c35467df1cc7a57205223e00afed3aaa8666ad12fc15087e2b619b1dbdd6df133fcce03fdc879262d519623735cbf4fba710420386707b5e36583074816199c2ef381cf484b6102df1f65b8cf639cbf737b0a2fb1be2011a74ff4e21a65c9486c0a773b688d81ce3f2dd2f8b22c511a05d0ad76ced3195241aa81ee19d5d8a7b9a8e2062810dcd3866282da42545a0d51069af690d253567281f1a4ca66cb12bae751da5a447e3ae66afc2b4750815f008f0bf90b72827cf89891942522eb809f6644f1ef8dfb7129a1b4f61018dde80a8659e12e25d8a0f009a6058f35e3f2f897ef48b215232033211838ee9c56075117e5f3bfb85ab85c534c864a16a3b3f5d130848074d55a3d1b42fe40b7c3e58635316d59858e3679346ba642f46c64ce1063871e714cd294a045f5bc5449f70f3df7e38664b5a24bae673c97b9823bccf710ca91133b77ec7c237f96a9327e6108c0f16a10d064c6111f854726edf52b3e4f8ae0eae69e24ba5e278461a4cca26aa8a72
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(34322);
 script_version("1.2");

 script_cve_id("CVE-2008-4095");
 script_bugtraq_id(31505);

 name["english"] = "Mac OS X : Flip4Mac < 2.2.1 Unspecified Vulnerability";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability in its WMV decoder." );
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Flip4Mac that
contains an unspecified vulnerability in its decoder. 

Flip4Mac is an extension that lets users read '.wmv' movie files.  By
enticing a user on the remote host to read a malformed '.wmv' file, an
attacker may be able to execute arbitrary commands on the remote
system." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1935549" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Flip4Mac Version 2.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Check for Flip4Mac on the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function _GetBundleVersionCmdInfo(file, path, label )
{
  local_var ret, suffix;
  local_var cmd;

   suffix = "/Contents/Info.plist";
   cmd    = "cat";
 

 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && "; 
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
;
 return ret;
}


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
if ( egrep(pattern:"Darwin.* ", string:uname) )
{
 cmd = _GetBundleVersionCmdInfo(file:"Flip4Mac WMV Import.component", path:"/Library/QuickTime", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 2.2.1.11
 if ( int(array[0]) < 2 ||
     (int(array[0]) == 2 && int(array[1]) < 2 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) < 1 ) || 
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) == 1 && int(array[3]) < 11 ) )
 {
   security_hole(0);
 }
}
