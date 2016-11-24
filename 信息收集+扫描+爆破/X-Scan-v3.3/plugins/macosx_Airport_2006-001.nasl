#TRUSTED 692bfeb5a77b11595c1826e095da564ea0417050bb977b3fb91f32397e5785c6e6e7d2f508018b28c3788fc2035f537cabba72a224c6447b314ebf951ea9e5fd4f8493d676a990d3618fa079fef88d2a3154f14c162214701a0879fd095600a9137e984a09ab0d4624cdfba4a49508afa2518fe43d70f4593996ff76430d6d972113a1966039646f2dce52b778bd22ec6e4dc1adbabe8ef0957e8494f30b0b055cd07052626ef8b6077ee9d3d6dc4faa0e91c7d78f7d123ac429502553834ef125dab2d28b472babaaf2566bd29ecf04126d5042d1d1bc0db91fdfa70565fc88d372b9c5a7607aaf1dd554206ca287d4d9f59fcc8662dc827790689d4a6cff337efd4662907ac5451621db420c101df5ab0f1edabf75fe55c71afb0065e0235524d7d12ac02ace42c39d59bb68e85dd8a81b37903d99df96b9ca7ebeee4ecedfad72edf19c515db023440f94cfb5b316a92515b283fa3c1c91893c36edcfc62b7617d3beaaa1347f8032801af035169b373a603a931784364cb8032a10d6db4fd12a5bacf1fef8faad224c7116a2663f9d0c5ea98a1524bf9bb5f0be66c6e3f66db96c8f6e0dfcf7426d0c706c3f6acd133824c9a28125ca0f7310faabd7d40e023a800f92f2e347ce824b2e80feff5349ab98f74fe4042a48375a4157e17931fa2697500e490519d98891ea2f5ccc5e7798eb478e45eb95244b3404d7548e4b
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(22418);
 script_version ("1.15");

 script_cve_id("CVE-2006-3507", "CVE-2006-3508", "CVE-2006-3509");
 script_bugtraq_id(20144);
 script_xref(name:"OSVDB", value:"29061");
 script_xref(name:"OSVDB", value:"29062");
 script_xref(name:"OSVDB", value:"29063");
 
 script_name(english:"AirPort Update 2006-001 / Security Update 2006-005");
 script_summary(english:"Checks for the version of the Airport drivers");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the AirPort
Wireless card." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security update regarding the drivers of
the AirPort wireless card. 

An attacker in the proximity of the target host may exploit this flaw
by sending malformed 802.11 frames to the remote host and cause a
stack overflow resulting in a crash of arbitrary code execution." );
 script_set_attribute(attribute:"solution", value:
"Apple has released a patch for this issue :

http://docs.info.apple.com/article.html?artnum=304420" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
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

function vulnerable()
{
 security_hole( port : 0 );
 if ( ! islocalhost() ) ssh_close_connection();
 exit(0);
}
 
function cmd()
{
 local_var buf;
 local_var ret;

 if ( islocalhost() )
	return pread(cmd:"bash", argv:make_list("bash", "-c", _FCT_ANON_ARGS[0]));
 
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:_FCT_ANON_ARGS[0]);
 ssh_close_connection();
 return buf;
}


uname = get_kb_item("Host/uname");
if ( "Darwin" >!< uname ) exit(0);


#
# Mac OS X < 10.4.7 is affected
#
if ( uname =~ "Version 8\.[0-6]\." ) vulnerable();

#
# Mac OS X < 10.3.9 is affected
# 
if ( uname =~ "Version 7\.[0-8]\." ) vulnerable();



get_build   = "system_profiler SPSoftwareDataType";
has_airport = "system_profiler SPAirPortDataType";
atheros  = GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");
broadcom = GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");


  
build = cmd(get_build);
airport = cmd(has_airport);
if ( "Wireless Card Type: AirPort" >!< airport ) exit(0);  # No airport card installed

#
# AirPort Update 2006-001
#	-> Mac OS X 10.4.7 Build 8J2135 and 8J2135a
#
if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J2135a?", string:build) )
{
 atheros_version = cmd(atheros);
 broadcom_version = cmd(broadcom);
 if ( atheros_version =~ "^1\." )
	{
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
	}
 if ( broadcom =~ "^1\." )
	{
	 v = split(broadcom_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 4 ) vulnerable();
	}
}
#
# Mac OS X Security Update 2006-005 (Tiger)
#	-> Mac OS X 10.4.7 build 8J135
#	-> Mac OS X 10.3.9 build 7W98
#
else if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J135", string:build) ||
          egrep(pattern:"System Version: Mac OS X 10\.3\.9 ", string:build) )
{
  cmd = GetBundleVersionCmd(file:"/AppleAirPort2.kext", path:"/System/Library/Extensions");
  airport_version = cmd(cmd);
  if ( airport_version =~ "^4\. " )
  {
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 4 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
  }
}


if ( ! islocalhost() ) ssh_close_connection();
