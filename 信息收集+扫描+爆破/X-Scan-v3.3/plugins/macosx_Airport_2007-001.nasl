#TRUSTED 1ec7f595c1ef3b4bcb62139bb11304521891b40cc44501bb1c96da34ca9ce0e4643caddb59a79ac7ab1f88f330f9df8d6b3b41720134980b048313ae370c8a152139d07301698e451e9904f1f067bcad3dd510e42af04943de477caf3dfe85abcd0697438f41483347b9c9735de8bccb358cb10c55a3f9e5c01228243634fdc42fb83bbff0a307524ec0ff2937bd938b2bedf27a81303409419f4c1a7bb2162a42998627c97209980a800c7824225408f96e7dcc84f311689598d48c479d70a7dc3fcaf32ce64956148cbcc670249ca9d5dde8e19920fad43ea38e8937bb7c4d111b81d794f2ad7be339a7e61cc0e4ac500fbac9f32a8d7f8c378e8cde30b70c4e6609d089acf422e0ab763cdd5c6f4e77da94da7dbf313ce116a189e297cb149480a5ad121ad293811055fcd0eda34eec206ef6d4a467d16ae479acc1be1fe3543c9554041bdaee3e182b6e22ad1865e723f6138ffe5a802273d171d6fe77bd4a4618fcfd5c3326ac78b2b51a6490b540be28803473f24b1fe5ffc1ae8e1ecd6d8a4fd62bc3439e66df329c403026bed146f8b9fe569303d2f03b0d71f10ef68c83ca996fd3708291c14bd9ee33da1067ec75751626f31b15a4797614871dbbd1303b816e26f336e0ae47e9dd0ef194169a43a7a0e3f1800f1fe50675f04c4bba53cf1aafc06c5f9990e400706031c8efb6dcea64708bb31dc703de7bed1d79
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24241);
 script_version ("1.8");

 script_cve_id("CVE-2006-6292");
 script_bugtraq_id(21383);
 script_xref(name:"OSVDB", value:"30724");

 script_name(english:"Mac OS X Airport Update 2007-001");
 script_summary(english:"Check for the presence of the SecUpdate 2007-001");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not have
Airport Update 2007-001 applied.

This update fixes a flaw in the wireless drivers that may allow an
attacker to crash a host by sending a malformed frame." );
 script_set_attribute(attribute:"solution", value:
"Install Airport Update 2007-001 :

http://www.nessus.org/u?0af16cb0" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305031" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C" );
 script_end_attributes();
 
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


 buf = chomp(buf);
 return buf;
}

uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);
if ( ! egrep(pattern:"Darwin.* (8\.)", string:uname) ) exit(0);

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
if ( 
  "AirPortExtremeUpdate2007001.pkg" >< packages ||
  "AirPortExtremeUpdate2007002.pkg" >< packages ||
  "AirPortExtremeUpdate2007003.pkg" >< packages ||
  "AirPortExtremeUpdate2007004.pkg" >< packages ||
  "AirPortExtremeUpdate200800" >< packages
) exit(0);

buf = exec(cmd:"system_profiler SPHardwareDataType");
if ( ! buf )exit(0);
if ("Intel Core Duo" >!< buf ) exit(0); # Only Core [1] Duo affected


cmd = _GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && int(buf) < 2214600 ) { security_warning(0); exit(0); }

cmd = _GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && int(buf) < 2217601 ) { security_warning(0); exit(0); }
