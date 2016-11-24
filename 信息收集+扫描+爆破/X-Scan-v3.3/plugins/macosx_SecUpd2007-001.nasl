#TRUSTED 524f4c5778366925189d4e529ba3104b0d85ec9609daf643f5045e260fd7f773cf67a7e6e61809883229b8de83730dbda5280f0ce36068ecca8468ed641032bd88f1cb78b4d853634acbe8114e3d42b72dbaa4f36a1ffcea856c85bc0bb7748187099f63a76eaee31a268b622038e9eefd8306c2b67d569a94113fa2c72aeaea9607bc8600409ccfd2959e1a981d5c1ce559c998f31a4e4d5b96a5618ce78b2dba1f307c13e6420a5610ffc775a9594431f272168262c2ab89e6f520d3eee813ad6d025ab3f2032230a09ea09a0fa0171d9e695c52c86398eeecc5d2c9fe4d87cef68c773e76ac4b1429a8726ff55c61f909e1348e34e9221444f7b991977081970f2abb32e0a6991fc82c12ff34be18481de1081ff24bfa572bde993fa6579ed823eda29799492e742958fb6f5298c1af7a91f1701fb4359e64a3280a9ee963bd18c53d358f4ffd305cdc17d17dc9d9723a25d366de3aad9f1fe448f54ae0aa40c3da56040ef06009cd4ef624125c801623737492d93cb1f78eee7197e91466778a2c5922c1bb7407707a005902795845b521831a50e9d62143d5647e0aa70ce6325b3c829a97f7863e25216b4308d4ca43a4fcfa1df5496c32429b393ba76da594692fcd8ee7d6171a25f94e6b7f44e40e083465b28079dd552502ce2ce01b8fd43f83fa9563a8e58e325dd300d3d6b51aac3874735ca00c7e7368f61cf914
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24234);
 script_version ("1.8");

 script_cve_id("CVE-2007-0015");
 script_bugtraq_id(21829);
 script_xref(name:"OSVDB", value:"31023");

 name["english"] = "Mac OS X Security Update 2007-001";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3 or 10.4 which
does not have the security update 2007-001 applied. 

This update fixes a flaw in QuickTime which may allow a rogue website
to execute arbitrary code on the remote host by exploiting an overflow
in the RTSP URL handler." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304989" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2007-001 :

http://www.apple.com/support/downloads/securityupdate2007001universal.html
http://www.apple.com/support/downloads/securityupdate2007001panther.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Check for the presence of the SecUpdate 2007-001";
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
 local_var buf, ret, soc;

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

# Look at the exact version of QuickTimeStreaming
cmd = GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime");
buf = exec(cmd:cmd);
set_kb_item(name:"MacOSX/QuickTimeSteaming/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 7 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 3 ) ) {
	 security_warning( 0 );
	exit(0);
}
else if ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) == 3 ) 
{
 cmd = _GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) < 4650200 ) security_warning(0);
}
 
