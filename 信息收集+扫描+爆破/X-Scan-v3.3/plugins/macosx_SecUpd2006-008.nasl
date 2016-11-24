#TRUSTED b1492db04d1da5e74142f42c45d67e0d641f9dcf07ba4d41793c0ad60efc246e44fd6649f50649da8b61aa25e35b7bdaa166dde154847f8a2911758d88626fd5d1876a1a8cbfbf0b7f00606cd10557e96135591807069ab3d19d0360cfb82048977296bd33c1ce7f1dbff6cf806ea0431a2751df66f1c7b46ae932f76763b9fa2fb4b37571c79d68d5c68304a3e0ce7f5e9c4d76e90bf09782e207672db68da749ee8c7002e91973dccae149f68795290b438f0296688bd53cfc4cea008cf2a47d32952e3b302ac936c3f810f6111d17cfa9117701c1db9d4f80e7d11eb678e43d8ed2c9ab3f8b77edbcf87589c5b1661641988fcfc73652fd960dbf90f3c374b988439d6c28ca45aadcee94d00d6c5b0e35b4a84def2896c998975bdfe40a471445a90c143871e65e7a75cc37c1a0612fd6aca21a773c1422e4e15b0239b925cff3d9dfc76689b9e1221f55a38682dd3ddfe1a99c9c20d6b6cca103d9809df9d01babcb05304f0efd0dde40c583a52bacff6a975825834e96c7319c667ff87ce5c0fa861390d4a9648afe6ccde2fb10e8ef481f048c3701bb26caae8c093cc3ea8b61f759960175323bb5ef152fc9e2ede7c0e11daed01d688c60df8ffaa65bb47961fb6875e34855ea9f45639cb362aa080595a8fb70f2444edba8c012b67e3a29446ee49bba5db78129796ee8e690aa12a8151f3a3432266d02514f9ffa07
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(23926);
 script_version("1.6");

 script_cve_id("CVE-2006-5681");
 script_bugtraq_id(21672);
 script_xref(name:"OSVDB", value:"32380");

 name["english"] = "Mac OS X Security Update 2006-008";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2006-008 applied. 

This update fixes a flaw in QuickTime that may allow a rogue website
to obtain the images rendered on the user screen.  By combining this
flaw with Quartz Composer, an attacker may be able to obtain screen
shots of the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304916" );
 script_set_attribute(attribute:"solution", value:
"Install the security update 2006-008 :

http://www.apple.com/support/downloads/securityupdate2006008universal.html
http://www.apple.com/support/downloads/securityupdate2006008ppc.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Check for the presence of SecUpdate 2006-008";
 script_summary(english:summary["english"]);
 
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

# Look at the exact version of QuartzComposer
cmd = GetBundleVersionCmd(file:"QuartzComposer.component", path:"/System/Library/Quicktime", long:TRUE);

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

set_kb_item(name:"MacOSX/QuickTimeQuartzComposer/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 22 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 22 && int(version[1]) == 1 && int(version[2]) < 3 ) ) security_note( 0 );
